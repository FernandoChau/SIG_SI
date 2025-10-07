# SIG_IS — Steganography Web App

## Preparação local (Linux / macOS / WSL / Windows Git Bash)

1. Clone ou extraia o projeto e entre na pasta `SIG_IS`.
2. Crie um ambiente virtual e ative-o::
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux / macOS / WSL
   venv\Scripts\activate    # Windows (PowerShell)
   ```
3. Instale dependências:
   ```bash
   pip install -r requirements.txt
   ```
4. Copie o `.env.example` para `.env` e ajuste se necessário (por exemplo `SECRET_KEY`):
   ```bash
   cp .env.example .env
   ```
5. Execute localmente:
   ```bash
   python app.py
   ```
6. Abra http://127.0.0.1:5000 no browser.

## Deploy no Railway (resumo)
1. Faça login no Railway e crie um novo project — escolha "Deploy from GitHub" ou faça upload do repositório.
2. Se fizer upload, a aplicação será detectada. Configure as Environment Variables (vai usar `SECRET_KEY`, `PORT` e `FLASK_ENV`).
3. Para execução, Railway executa `web: gunicorn app:app` (já definido no Procfile). Se preferir use o `start.sh` como comando de start.
4. Defina `PORT` (Railway normalmente fornece uma variável `PORT`). A app já usa `os.environ.get('PORT', 5000)`.
5. Depois do deploy, abra a URL pública fornecida pela Railway.

## Notas
- UI usa Tailwind CDN e Alpine.js (apenas para protótipo académico). Para produção recomenda-se build local de assets.
- A senha mínima é 8 caracteres e é usada para derivar a chave que cifra a mensagem (AES-GCM).
- Não inclua ficheiros sensíveis no repositório público (ex.: chaves privadas).
