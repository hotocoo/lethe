# Scripted end-to-end driving (`--e2e-script`)

Lethe can drive itself the way a user would and assert what the user would
see, without Accessibility permissions or a test harness around the window
system. The same command language runs on macOS (AppKit shell) and Linux
(GTK shell):

```bash
# macOS
./build/lethe.app/Contents/MacOS/lethe --e2e-script tests/e2e/basic.lethe
# Linux (headless)
xvfb-run -a ./build-linux/lethe --e2e-script tests/e2e/basic.lethe
```

Exit status is 0 when every assertion held, 1 otherwise; the first failing
step stops the run and writes `lethe-e2e-failure.png` to the temp dir.

## Commands

One per line, `#` starts a comment. `<text>` runs to end of line.

| Command | Meaning |
|---|---|
| `load <text>` | Address-bar semantics: URL, bare host, or search query |
| `type-address <text>` | Type into the address bar and press Enter |
| `wait [ms]` | Until the current tab finished loading (page load or reader fetch); default 20000 |
| `try-wait [ms]` | Like `wait`, but a timeout logs `[e2e] timeout ...`, stops the load and continues (benchmark data point, not a failure) |
| `sleep <ms>` | Fixed pause |
| `newtab [text]` | Open a tab beside the current one; it becomes current |
| `closetab` | Close the current tab |
| `back` / `forward` / `reload` | Session history / reload |
| `reader` | Toggle reader view |
| `click <css>` | `document.querySelector(css).click()` |
| `js <code>` | Evaluate JavaScript (result kept) |
| `wait-js <ms> <code>` | Poll every 250 ms until `code` is truthy; fail after `ms` |
| `print-js <code>` | Evaluate and echo `[e2e] result <text>` on stdout (harness output) |
| `mark <text>` | Echo `[e2e] mark <text>` on stdout (harness synchronisation point) |
| `screenshot <path.png>` | Capture the window (`$TMPDIR/` prefix expands) |
| `assert-url-contains <s>` | Current URL or shown address contains `s` |
| `assert-title-contains <s>` | Window/tab title contains `s` (case-insensitive) |
| `assert-body-contains <s>` | `document.body.innerText` contains `s` |
| `assert-tabs <n>` | Exactly `n` tabs in the window |
| `assert-reader on|off` | Reader view state |
| `assert-js <code>` | JavaScript evaluates truthy |
| `quit` | Finish (exit code reflects failures) |

`tests/e2e/basic.lethe` is the release checklist: page load, link
navigation, history, address-bar search, tabs, a JavaScript-heavy site
(YouTube), private-network refusal with its named reason, secure-DNS
failure refusal, reader view round trip, and `target=_blank` opening a tab.
