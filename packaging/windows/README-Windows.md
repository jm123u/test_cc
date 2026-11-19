# TraceQuarry Portable for Windows

Runs on 64-bit Windows 10/11 with **no Python installation**, no Docker, and
no other dependencies.

## Quick start

1. **Extract the whole ZIP** to any folder. Do not run it from inside the
   archive.
2. Double-click `TraceQuarry.exe`.
3. A console window appears and your browser opens `http://127.0.0.1:8765/`.
4. When you are done, close the console window (or press `Ctrl+C`) to stop.

On first run, Windows SmartScreen may warn about an unknown publisher because
the launcher is not code-signed. Choose "More info" then "Run anyway". To avoid
the prompt, right-click the ZIP, open Properties, tick "Unblock", and only then
extract it. If Windows Firewall asks for network access you can deny it:
TraceQuarry listens only on the loopback address `127.0.0.1`.

## Folder layout

| Path | Purpose |
| --- | --- |
| `TraceQuarry.exe` | Starts the local web GUI |
| `tracequarry-cli.exe` | Command-line parser, e.g. `tracequarry-cli.exe --input x.tar.gz --out out` |
| `data\` | Created on first run: uploaded evidence, parser output, case repository |
| `evidence\` | Evidence placed here (or under your user profile) can be loaded by path |
| `app\` | TraceQuarry sources, rules (`rules\*.yml`), and web assets |
| `runtime\` | Bundled official CPython 3.12 runtime |

If the program folder is not writable (for example `C:\Program Files`), data is
stored in `%LOCALAPPDATA%\TraceQuarry\data` instead. Set the
`TRACEQUARRY_DATA_DIR` environment variable to choose another location.

## Launch options

`TraceQuarry.exe` accepts every `tracequarry-web` option plus `--no-browser`:

```bat
TraceQuarry.exe --port 9000 --no-browser
TraceQuarry.exe --input-root D:\cases --max-upload-gib 16
TraceQuarry.exe --help
```

- The default port is 8765. If it is busy, the next free port is used.
- If an instance is already running, starting it again only opens the browser.
- By default, evidence can be loaded by path from `evidence\` and from your
  user profile. Use `--input-root` (repeatable) for other locations.

## Differences from a source install

- The runtime is fully isolated: it ignores any installed Python, the registry,
  and `PYTHONPATH`.
- `tzdata` is bundled. Windows has no system IANA time-zone database, so zone
  names such as `Asia/Shanghai` cannot be resolved without it.
- `zstandard` is bundled so Zstandard-compressed fields in native systemd
  journal files are decoded.
- The standard library and the application are precompiled to bytecode for a
  faster start and fewer files.

## Security boundary

Same as upstream: TraceQuarry is a single-user, loopback-only tool with no
authentication. **Do not** expose its port to a LAN or the Internet. Keep the
original evidence preserved separately.

Licensed under Apache-2.0; see `licenses\`.
