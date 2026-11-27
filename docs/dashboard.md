# Dashboard

`safeclaw dashboard` serves the dashboard at http://localhost:7680 (bound to `127.0.0.1`, `--port` to change).

## How it works

Pages and fragments are rendered on the server with `html/template`. [htmx 4](https://htmx.org) handles requests and swaps, and its SSE extension handles live updates. htmx and the extension are vendored in `internal/dashboard/static` and embedded in the binary. The only hand-written JavaScript is `static/app.js`, which opens and closes the `<dialog>` modals, copies the attach command to the clipboard, refreshes an iframe, and normalizes the session name as you type.

## Live updates

The server runs one `docker events` stream, restarted a second after it exits. Whenever a `safeclaw-*` container is created, started, stopped, dies, or is destroyed, it sends a `sessions` event to every browser on `/events`. The page then re-fetches the sessions table and the frames grid and morphs them into place (`innerMorph`/`outerMorph`). Unchanged iframes keep their DOM node, so running terminals don't reconnect when another session changes.

Sandboxes are listed in the table with a `sandbox` badge and only their stop or delete button. They have no URL, info dialog, start button, or iframe, and start and info return 409 for them. Create refuses a sandbox's name like any other taken name. One-off sandboxes also get a `one-off` badge, and stopping one removes its row, because docker removes the container when it stops.

The new session dialog has an image variant picker listing `base` and every [variant](architecture.md#image-variants). Its first option, `default`, sends no variant, so the session gets the configured default, named in the option. Sessions and sandboxes on a variant show a badge with its name. Variants are read from the config file on every page load; if the file is invalid, the picker shows only `default` along with the error.

Dashboard actions respond with `HX-Trigger: sessions`, so the page also refreshes right away without waiting for the docker event.

## Two-click confirm

Stop and delete need two clicks. The first POST returns a "stop?"/"delete?" button that posts with `confirm=1`. That button also contains an element that fetches the normal button again after 3 seconds, which reverts it if you don't confirm.

## Routes

| Route | Purpose |
|-------|---------|
| `GET /` | Full page |
| `GET /fragments/sessions`, `GET /fragments/frames` | Table (or empty state) and frames grid |
| `GET /events` | SSE stream of `sessions` events |
| `POST /sessions` | Create a session (`name`, `volume`, `variant`, `query`, `open_tab`). Errors return 422 and render in the dialog |
| `GET /sessions/validate?name=` | Name hint shown while typing |
| `GET /sessions/{name}/info` | Session info dialog with the `docker exec` attach command |
| `GET /sessions/{name}/actions` | Normal action button, used to revert a confirm |
| `POST /sessions/{name}/start`, `/stop`, `/delete` | Session actions |

The JSON API from upstream is kept for scripting:

| Route | Body | Response |
|-------|------|----------|
| `GET /api/sessions` | | `[{name, port, url, volume, active, type, variant, autoRemove}]`, `type` is `session` or `sandbox`, `variant` is the image variant (`""` for the base image), `autoRemove` is true for one-off sandboxes |
| `POST /api/start` | `{"name"}` | `{success, url}`, or 409 for a sandbox |
| `POST /api/stop` | `{"name"}` | `{success}` |
| `POST /api/delete` | `{"name"}` | `{success}` |
| `POST /api/create` | `{"name", "volume", "variant", "query"}` | `{success, url}` or `{success: false, error}`, with 409 for a sandbox name |
| `GET /api/events` | | SSE, `data: <docker action>` |

## Security

Every request must use a loopback `Host` (`localhost`, `127.0.0.1`, `::1`), which blocks DNS rebinding. State-changing requests go through Go's `http.CrossOriginProtection`, so other websites can't drive the dashboard from your browser.
