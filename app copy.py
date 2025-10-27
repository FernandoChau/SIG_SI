from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from PIL import Image
import io, struct, os, hashlib, secrets, random
import mimetypes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time

# In-memory temporary store for decoded embedded files (token -> {data, filename, mime, expiry})
embedded_store = {}

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'aaa51bcb0a2bf4a596fc8f87c18a8cca52cb82e58605591147d1e50a5a5a19f5')

# Helpers: bits conversion
def _bytes_to_bits(b: bytes) -> str:
    return ''.join(f"{byte:08b}" for byte in b)

def _bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8 != 0:
        bits = bits.ljust((len(bits) + 7) // 8 * 8, '0')
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

# KDF / AES (PBKDF2 + AES-GCM)
def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password_bytes)

def encrypt_message(password: str, plaintext: bytes):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return salt, nonce, ct

def decrypt_message(password: str, salt: bytes, nonce: bytes, ciphertext: bytes):
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# Embedding: header (32 bytes) sequential, ciphertext scattered by PRNG(seed=sha256(password+salt))
def embed_payload_in_image(image: Image.Image, salt: bytes, nonce: bytes, ciphertext: bytes, password: str) -> Image.Image:
    if image.mode not in ('RGB', 'RGBA'):
        image = image.convert('RGBA')
    width, height = image.size
    pixels = image.load()
    total_capacity = width * height * 3

    header = salt + nonce + struct.pack('>I', len(ciphertext))
    header_bits = _bytes_to_bits(header)
    ciphertext_bits = _bytes_to_bits(ciphertext)

    if len(header_bits) + len(ciphertext_bits) > total_capacity:
        raise ValueError('Imagem insuficiente para armazenar o payload encriptado')

    flat_index = 0
    payload_index = 0
    max_header = len(header_bits)
    for y in range(height):
        for x in range(width):
            if payload_index >= max_header:
                break
            pixel = list(pixels[x, y])
            for channel in range(3):
                if payload_index >= max_header:
                    break
                bit = int(header_bits[payload_index])
                pixel[channel] = (pixel[channel] & ~1) | bit
                payload_index += 1
                flat_index += 1
            pixels[x, y] = tuple(pixel)
        if payload_index >= max_header:
            break

    remaining_positions = list(range(flat_index, total_capacity))
    seed_material = hashlib.sha256(password.encode('utf-8') + salt).digest()
    seed_int = int.from_bytes(seed_material, 'big')
    rng = random.Random(seed_int)
    rng.shuffle(remaining_positions)

    if len(ciphertext_bits) > len(remaining_positions):
        raise ValueError('Capacidade insuficiente após header')

    for i, bit_char in enumerate(ciphertext_bits):
        pos = remaining_positions[i]
        bit = int(bit_char)
        pixel_idx = pos // 3
        channel = pos % 3
        x = pixel_idx % width
        y = pixel_idx // width
        pixel = list(pixels[x, y])
        pixel[channel] = (pixel[channel] & ~1) | bit
        pixels[x, y] = tuple(pixel)

    return image

def extract_payload_from_image(image: Image.Image, password: str) -> bytes:
    if image.mode not in ('RGB', 'RGBA'):
        image = image.convert('RGBA')
    width, height = image.size
    pixels = image.load()
    total_capacity = width * height * 3

    header_bits = ''
    bits_read = 0
    for y in range(height):
        for x in range(width):
            pixel = pixels[x, y]
            for channel in range(3):
                header_bits += str(pixel[channel] & 1)
                bits_read += 1
                if bits_read >= 256:
                    break
            if bits_read >= 256:
                break
        if bits_read >= 256:
            break

    header_bytes = _bits_to_bytes(header_bits)
    salt = header_bytes[0:16]
    nonce = header_bytes[16:28]
    ct_len = struct.unpack('>I', header_bytes[28:32])[0]

    flat_index_start = 256
    remaining_positions = list(range(flat_index_start, total_capacity))
    seed_material = hashlib.sha256(password.encode('utf-8') + salt).digest()
    seed_int = int.from_bytes(seed_material, 'big')
    rng = random.Random(seed_int)
    rng.shuffle(remaining_positions)

    ct_bits_needed = ct_len * 8
    if ct_bits_needed > len(remaining_positions):
        raise ValueError('A imagem não contém bits suficientes para o ciphertext declarado')

    ct_bits = ['0'] * ct_bits_needed
    for i in range(ct_bits_needed):
        pos = remaining_positions[i]
        pixel_idx = pos // 3
        channel = pos % 3
        x = pixel_idx % width
        y = pixel_idx // width
        pixel = pixels[x, y]
        ct_bits[i] = str(pixel[channel] & 1)

    ciphertext = _bits_to_bytes(''.join(ct_bits))
    plaintext = decrypt_message(password, salt, nonce, ciphertext)
    return plaintext

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/proteger')
def proteger():
    return render_template('form-elements.html')

@app.route('/mostrar')
def mostrar():
    return render_template('forms.html')

@app.route('/encode', methods=['POST'])
def encode():
    file = request.files.get('image')
    message = request.form.get('message', '') or ''
    password = request.form.get('password', '') or ''
    password_confirm = request.form.get('password_confirm', '') or ''
    embed_type = request.form.get('embed_type', 'text') or 'text'

    if not file or file.filename == '':
        flash('Por favor envie uma imagem PNG.')
        return redirect(url_for('proteger'))

    filename = file.filename.lower()
    if not filename.endswith('.png'):
        flash('Por favor envie uma imagem PNG (formato .png).')
        return redirect(url_for('proteger'))

    if not password or len(password) < 8:
        flash('A senha deve ter pelo menos 8 caracteres.')
        return redirect(url_for('proteger'))

    if password != password_confirm:
        flash('As senhas não coincidem.')
        return redirect(url_for('proteger'))

    try:
        image = Image.open(file.stream).convert('RGBA')
        # Build plaintext structure: 1 byte type, 4 bytes filename length, filename bytes, payload bytes
        if embed_type == 'text':
            if not message:
                flash('Por favor forneça a mensagem de texto a embutir.')
                return redirect(url_for('proteger'))
            type_flag = b'\x00'
            filename_bytes = b''
            payload_bytes = message.encode('utf-8')
        else:
            # file embedding
            payload_file = request.files.get('payload')
            if not payload_file or payload_file.filename == '':
                flash('Por favor envie um ficheiro para embutir.')
                return redirect(url_for('proteger'))
            type_flag = b'\x01'
            filename_bytes = (payload_file.filename or '').encode('utf-8')
            payload_bytes = payload_file.read()

        plaintext = type_flag + struct.pack('>I', len(filename_bytes)) + filename_bytes + payload_bytes
        salt, nonce, ciphertext = encrypt_message(password, plaintext)

        width, height = image.size
        total_capacity = width * height * 3
        header_bits_len = 32 * 8
        if header_bits_len + len(ciphertext) * 8 > total_capacity:
            flash('A imagem não tem capacidade suficiente para a mensagem fornecida. Use uma imagem maior.')
            return redirect(url_for('proteger'))

        # Use the provided password to seed the PRNG for scattering ciphertext bits
        encoded = embed_payload_in_image(image, salt, nonce, ciphertext, password)
        img_io = io.BytesIO()
        encoded.save(img_io, 'PNG')
        img_io.seek(0)
        return send_file(img_io, mimetype='image/png', as_attachment=True, download_name='encoded.png')
    except Exception as e:
        flash(f'Erro ao encodar: {e}')
        return redirect(url_for('proteger'))

@app.route('/decode', methods=['POST'])
def decode():
    
    file = request.files.get('image')
    password = request.form.get('password', '') or ''

    # displplay password for testing
    print("Password received for decoding:", password)
    print("Password received for file:", file)

    if not file or file.filename == '':
        flash('Por favor envie uma imagem PNG.')
        return redirect(url_for('mostrar'))

    if not password or len(password) < 8:
        flash('Por favor forneça a senha usada para cifrar (mínimo 8 caracteres).')
        return redirect(url_for('mostrar'))

    try:
        image = Image.open(file.stream).convert('RGBA')
        plaintext = extract_payload_from_image(image, password)

        # Parse plaintext structure
        if len(plaintext) < 5:
            raise ValueError('Payload inválido')
        type_flag = plaintext[0]
        filename_len = struct.unpack('>I', plaintext[1:5])[0]
        filename = ''
        payload_start = 5
        if filename_len:
            filename = plaintext[payload_start:payload_start+filename_len].decode('utf-8', errors='ignore')
            payload_start += filename_len
        payload = plaintext[payload_start:]

        if type_flag == 0:
            # text
            message = payload.decode('utf-8', errors='replace')
            return render_template('result.html', message=message)
        else:
            # file/media: store temporarily and render a download page with token
            if not filename:
                filename = 'extracted.bin'
            mime_type, _ = mimetypes.guess_type(filename)
            if not mime_type:
                mime_type = 'application/octet-stream'
            token = secrets.token_urlsafe(24)
            # expiry in 5 minutes
            embedded_store[token] = {
                'data': payload,
                'filename': filename,
                'mime': mime_type,
                'expiry': time.time() + 300
            }
            return render_template('result_file.html', filename=filename, size=len(payload), token=token)
    except Exception as e:
        flash('Senha incorreta ou mensagem danificada. Verifique a senha e a integridade da imagem.')
        return redirect(url_for('mostrar'))


@app.route('/download/<token>')
def download_token(token: str):
    info = embedded_store.get(token)
    if not info:
        flash('Ficheiro expirado ou inválido.')
        return redirect(url_for('mostrar'))
    if info['expiry'] < time.time():
        # expired
        del embedded_store[token]
        flash('Ficheiro expirou.')
        return redirect(url_for('mostrar'))
    data = info['data']
    filename = info['filename']
    mime = info['mime']
    # optionally remove after first download
    del embedded_store[token]
    return send_file(io.BytesIO(data), as_attachment=True, download_name=filename, mimetype=mime)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
