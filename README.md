# honeypot-agent

Cross-platform CLI that deploys honeytokens (decoy files and credentials) and detects tampering or reads via filesystem metadata and content hashing.

## Build

SQLite support in `github.com/mattn/go-sqlite3` requires CGO and a C toolchain (e.g. Xcode CLI tools on macOS, `gcc` on Linux, MinGW on Windows).

```bash
CGO_ENABLED=1 go build -o agent ./cmd/agent
```

Module path: `github.com/misherr2004/honeypot-agent`.

After cloning, run:

```bash
CGO_ENABLED=1 go mod tidy
```

## Usage

All commands use the standard library `flag` package (`--name=value`).

### place

File token:

```bash
./agent place --type=file --path=/tmp/secret.txt --content="password=supersecret123"
```

Registry-style credential (real registry on Windows; marker `.reg` file under `~/.honeypot/registry/` on Linux/macOS):

```bash
./agent place --type=credential --target=registry --name=HoneyUser --password=fakePass
```

Browser-style credential (JSON file under `~/.honeypot/browser/`):

```bash
./agent place --type=credential --target=browser --url=example.com --login=honey
```

Optional `--password` applies to browser tokens (default is a built-in fake secret).

### check

Scans every stored token, updates `status` and `checked_at`, and appends a JSON line to the activation log when a token looks compromised (`deleted`, `modified`, or `accessed`).

```bash
./agent check
```

### list

Prints a fixed-width table of all tokens.

```bash
./agent list
```

## Data locations

| Item | Location |
|------|----------|
| SQLite database | `~/.honeypot/honeypot.db` |
| Activation log (primary) | `/var/log/honeypot/activations.log` (non-Windows; requires write access) |
| Activation log (fallback) | `~/.honeypot/activations.log` |

## Architecture

- **`cmd/agent`** — Thin entrypoint; calls `commands.Main`, which wires SQLite, the activation logger, signal handling, and dispatch.

- **`internal/commands`** — Subcommands `place`, `check`, and `list`; parses flags, validates options, selects the right `honeytoken.HoneyChecker`, and maps `store.Record` rows to `honeytoken.HoneyToken` for checks.

- **`internal/honeytoken`** — Core types (`HoneyToken`, `PlaceOptions`, `CheckResult`) and the `HoneyChecker` interface. `FileChecker`, `RegistryChecker`, and `BrowserChecker` implement placement and checking. File-like checks share `checkDecoyFile` (hash, missing file, atime vs mtime). Registry on Windows lives in `registry_windows.go` (`golang.org/x/sys/windows/registry`); on other OSes a marker file is used (`registry_unix.go`). Platform-specific atime logic is split with build tags (`file_atime_*.go`).

- **`internal/store`** — `Store` interface and `SQLiteStore` with schema migration on open; keeps persistence mock-friendly.

- **`internal/logger`** — Newline-delimited JSON activation records; tries `/var/log/honeypot` first, then the home-directory fallback.

## Tests

```bash
CGO_ENABLED=1 go test ./...
```

## License

Add your preferred license.
