# lethe

Built-in browser for Aletheia platform using custom Chromium engine.

## Build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j$(nproc)
```

## Structure

- `src/` — main application code
- `browser/` — browser process logic
- `renderer/` — renderer process bindings
- `include/` — public headers
