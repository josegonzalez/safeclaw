# Dashboard

`safeclaw dashboard` serves the dashboard on `127.0.0.1:7680` (`--port` to change) and prints a URL carrying a random token, such as `http://127.0.0.1:7680/?token=...`. Opening it logs the browser in with a cookie; every route, static files included, returns 401 without it. See [dashboard access](architecture.md#dashboard-access).

## How it works

Pages and fragments are rendered on the server with `html/template`. [htmx 4](https://htmx.org) handles requests and swaps, and its SSE extension handles live updates. htmx and the extension are vendored in `internal/dashboard/static` and embedded in the binary. The only hand-written JavaScript is `static/app.js`, which opens and closes the `<dialog>` modals, copies the attach command to the clipboard, refreshes an iframe, and normalizes the session name as you type.

## Live updates

The server runs one `docker events` stream of container and network events, restarted a second after it exits. Whenever a `safeclaw-*` container is created, started, stopped, dies, or is destroyed, or one is connected to or disconnected from a network (checked by container ID, since network events name the network), it sends a `sessions` event to every browser on `/events`. The page then re-fetches the sessions table and the frames grid and morphs them into place (`innerMorph`/`outerMorph`). Unchanged iframes keep their DOM node, so running terminals don't reconnect when another session changes.

Sandboxes are listed in the table with a `sandbox` badge and only their stop or delete button. They have no URL, info dialog, start button, or iframe, and start and info return 409 for them. Create refuses a sandbox's name like any other taken name. One-off sandboxes also get a `one-off` badge, and stopping one removes its row, because docker removes the container when it stops.

The new session dialog has an image variant picker listing `base` and every [variant](architecture.md#image-variants). Its first option, `default`, sends no variant, so the session gets the configured default, named in the option. Sessions and sandboxes on a variant show a badge with its name. Variants are read from the config file on every page load; if the file is invalid, the picker shows only `default` along with the error.

The dialog also has a secrets picker: `all secrets` (the default), `no secrets`, or `only checked` with a checkbox per stored secret. The checkboxes are only shown, with CSS `:has()`, while `only checked` is picked. Sessions that don't receive every secret show a `no secrets` or `N secrets` badge, with the names in its tooltip. Sandboxes never get one, since they never receive secrets. See [choosing secrets](architecture.md#choosing-secrets).

Interactive sessions have an `offline` or `online` button next to stop or delete, and in the frame bar. `offline` takes the session offline with the unnamed hold. `online` releases the unnamed hold; if other owners still hold the session, it turns into a `force online?` button listing them in its tooltip, which releases every hold when clicked, and reverts after 3 seconds otherwise. Offline sessions show an `offline` badge with their holders and reasons in its tooltip, `offline` in place of their URL, and a placeholder in place of the iframe, which comes back when they reconnect. See [offline sessions](architecture.md#offline-sessions).

A banner above the table says when no Claude Code token is stored, or when it has expired or expires within 30 days, and names `safeclaw auth login`. It re-fetches with the table on every `sessions` event. Storing a token fires no docker event, so the banner clears on the next session change or page load. See [Claude Code](architecture.md#claude-code).

Dashboard actions respond with `HX-Trigger: sessions`, so the page also refreshes right away without waiting for the docker event.

## Two-click confirm

Stop and delete need two clicks. The first POST returns a "stop?"/"delete?" button that posts with `confirm=1`. That button also contains an element that fetches the normal button again after 3 seconds, which reverts it if you don't confirm.

## Routes

| Route | Purpose |
|-------|---------|
| `GET /` | Full page |
| `GET /fragments/sessions`, `GET /fragments/frames` | Table (or empty state) and frames grid |
| `GET /fragments/auth` | Claude Code token banner, empty while the token is valid |
| `GET /events` | SSE stream of `sessions` events |
| `POST /sessions` | Create a session (`name`, `volume`, `variant`, `secrets` as `all`, `none`, or `only` with a `secret` field per name, `query`, `open_tab`). Errors return 422 and render in the dialog |
| `GET /sessions/validate?name=` | Name hint shown while typing |
| `GET /sessions/{name}/info` | Session info dialog with the `docker exec` attach command |
| `GET /sessions/{name}/actions` | Normal action button, used to revert a confirm |
| `POST /sessions/{name}/start`, `/stop`, `/delete` | Session actions |
| `POST /sessions/{name}/offline`, `/online` | Take a session offline with the unnamed hold, or release it (`force=1` releases every hold) |

The JSON API from upstream is kept for scripting. Send the token from `~/.config/safeclaw/dashboard/PORT.token` as a bearer token:

```bash
curl -H "Authorization: Bearer $(cat ~/.config/safeclaw/dashboard/7680.token)" http://localhost:7680/api/sessions
```


| Route | Body | Response |
|-------|------|----------|
| `GET /api/sessions` | | `[{name, port, url, volume, active, type, variant, autoRemove, secrets}]`, `type` is `session` or `sandbox`, `variant` is the image variant (`""` for the base image), `autoRemove` is true for one-off sandboxes, `secrets` is `null` for every secret or the list of names the session receives (`[]` for none), `network` is `online`, `offline`, `none`, `host`, or `shared`, and `holds` lists `{owner, reason, since}` for each hold keeping it offline (`owner` is `""` for the unnamed hold) |
| `POST /api/start` | `{"name"}` | `{success, url}`, or 409 for a sandbox |
| `POST /api/stop` | `{"name"}` | `{success}` |
| `POST /api/delete` | `{"name"}` | `{success}` |
| `POST /api/net/off` | `{"name", "owner", "reason"}` | `{success, offline, holds}`, or 409 for a sandbox or a network that can't be disconnected |
| `POST /api/net/on` | `{"name", "owner", "force"}` | `{success, offline, holds}`. `offline` stays true while other holds remain. 409 with the holders when `owner` holds nothing but others do |
| `POST /api/create` | `{"name", "volume", "variant", "secrets", "query"}` | `{success, url}` or `{success: false, error}`, with 409 for a sandbox name or when it would recreate an offline session. `secrets` is `"all"`, `"none"`, or a list of names; leaving it out keeps an existing session's set, or gives a new one every secret |
| `GET /api/events` | | SSE, `data: <docker action>` |

## Security

Every request must use a loopback `Host` (`localhost`, `127.0.0.1`, `::1`), which blocks DNS rebinding, and carry the launch token in the `safeclaw_dashboard_PORT` cookie or an `Authorization: Bearer` header, which keeps out code in session containers and other local processes. A `GET` with the token in its `token` query parameter sets the cookie and redirects to the same URL without it. State-changing requests also go through Go's `http.CrossOriginProtection`, so other websites can't drive the dashboard from your browser. The auth check is `Access.Middleware` in `internal/dashboard/access.go`, so routes added later get it by being on the same handler.
