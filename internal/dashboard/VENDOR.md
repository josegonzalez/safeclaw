# Vendored front-end files

These files in `static/` are copied unchanged from their npm packages and embedded in the binary. `TestVendoredFiles` checks each one against the SHA-256 below and fails when a file in `static/` other than `app.js` and `style.css` isn't listed. Dependabot can't track vendored files, so they are updated by hand, see [updating vendored files](../../docs/development.md#updating-vendored-front-end-files).

| File | Package | Version | Source | SHA-256 |
|------|---------|---------|--------|---------|
| `static/htmx.min.js` | `htmx.org` | 4.0.2 | https://cdn.jsdelivr.net/npm/htmx.org@4.0.2/dist/htmx.min.js | `fd25ba3fe5e44768756f23862a6daa4f928192199a121e825e882e719bc8aabd` |
| `static/ext/hx-sse.min.js` | `htmx.org` | 4.0.2 | https://cdn.jsdelivr.net/npm/htmx.org@4.0.2/dist/ext/hx-sse.min.js | `650d88a96a017a50ca0e16ffcf8663ca9ebd12a7e2e73ab22086540e5924ce5f` |
| `static/htmx-LICENSE` | `htmx.org` | 4.0.2 | https://cdn.jsdelivr.net/npm/htmx.org@4.0.2/LICENSE | `d3d2456f76414f2456104660ebd65aff1c04cd7966b942bdabd63f3cdb316a38` |
| `static/xterm/xterm.min.js` | `@xterm/xterm` | 5.5.0 | https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js | `7a88e46a58847d3f17109e3d48cc8aa056a01997d00ceb76035f63370712d858` |
| `static/xterm/xterm.css` | `@xterm/xterm` | 5.5.0 | https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css | `ba8e6985669488981ccf40c0cefe3aba80722cb6c92de7ad628b0bd717faf2b6` |
| `static/xterm/xterm-LICENSE` | `@xterm/xterm` | 5.5.0 | https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/LICENSE | `b569f629d00f2626a8100df2a1798210535621e42164dfd426a6fe5aac7b0ccd` |
| `static/xterm/addon-fit.min.js` | `@xterm/addon-fit` | 0.10.0 | https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.js | `3e9ae6f6965ee1269d5574b905cf1bf559c2f44c784255b0034a71387e7719c9` |
| `static/xterm/addon-fit-LICENSE` | `@xterm/addon-fit` | 0.10.0 | https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/LICENSE | `e256f01188af527e4d06d21d06fbf785ae9c50d4b328bf03cbe0ba7f0aa4228f` |
