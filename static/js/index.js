window.addEventListener('load', () => window.setTimeout(() => {
      const makeLink = (asset) => {
        const link = document.createElement('link')

        Object.keys(asset).forEach((attribute) => {
          link.setAttribute(attribute, asset[attribute])
        })

        return link
      }

      const loadNext = (assets, count) => window.setTimeout(() => {
        if (count > assets.length) {
          count = assets.length

          if (count === 0) {
            return
          }
        }

        const fragment = new DocumentFragment

        while (count > 0) {
          const link = makeLink(assets.shift())
          fragment.append(link)
          count--

          if (assets.length) {
            link.onload = () => loadNext(assets, 1)
            link.onerror = () => loadNext(assets, 1)
          }
        }

        document.head.append(fragment)
      })

      loadNext([], 3)
    }))