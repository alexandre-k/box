[![Rust](https://github.com/alexandre-k/box/actions/workflows/rust.yml/badge.svg)](https://github.com/alexandre-k/box/actions/workflows/rust.yml)

# `box` — KVM MicroVM Sandboxes with Transparent DNS Telemetry

`box` is a Rust CLI that launches hardware-isolated KVM microVM sandboxes (via Fedora Atomic's `crun-krun`/`libkrun` + `podman`, or Kata Containers + `nerdctl`) with strict filesystem/privilege hardening, composable toolchain presets, and rootless outbound DNS traffic auditing.

---

## Architecture Overview

```text
User CLI (`box ...`)
  │
  ├── --list              ──▶ runtime::list_boxes()         (podman/nerdctl ps --filter label=box.managed=true)
  ├── --verify            ──▶ runtime::verify_isolation()   (inspect host stack + live microVM kernel/virtiofs probe)
  ├── --inspect <box>     ──▶ inspect::inspect_box_stack()  (container runtime/Kata vs libkrun, image, OS, installed tools & packages)
  ├── --attach <box> (-a) ──▶ runtime::attach_box()         (attach if Up, start -ai if Exited, recreate if --mount-cwd/-d)
  ├── --traffic           ──▶ telemetry::show_traffic_dashboard()
  │   ├── --follow (-f)   ──▶ telemetry::follow_traffic()   (live color-coded terminal tail)
  │   └── --web           ──▶ web::serve_traffic_ui()       (live local browser UI via SSE)
  ├── --trace <domain>    ──▶ telemetry::trace_domain()
  ├── --dns-pcap-file ... ──▶ pcap::run_pcap_dns_auditor()  (internal background child mode)
  │
  └── <launch sandbox>    ──▶ runtime::run_box()
        │
        ├── 1. Validate /dev/kvm & target workspace path (refuses /, /home, $HOME, /etc, /var, /usr)
        ├── 2. Resolve image or build combined preset image (images::build_combined_image)
        ├── 3. If rootless krun + --net internet:
        │        spawn self with `--dns-pcap-file $XDG_RUNTIME_DIR/box-pcap-<name>-<pid>.pcap`
        └── 4. exec() into [systemd-run --user --scope --slice=podman-sandbox.slice] podman/nerdctl run ...
```

### Source Layout

| Module | Purpose |
| --- | --- |
| `src/main.rs` | Thin entrypoint that parses CLI arguments and dispatches to the selected mode. |
| `src/cli.rs` | `clap` CLI definition (`Cli`), `NetMode`, `VmRuntime`, and `Preset` metadata. |
| `src/runtime.rs` | KVM/runtime checks, workspace path validation, hardening flags, mounts, network config, `list_boxes`, `attach_box`, `verify_isolation`, and `run_box`. |
| `src/inspect.rs` | `--inspect <BOX>` full software stack report (OCI runtime / Kata vs libkrun, image metadata, live OS/kernel probe, installed compilers/tools & packages). |
| `src/images.rs` | Single-preset image lookup, combined multi-preset `Containerfile` generation and build caching, and image-to-environment inference. |
| `src/pcap.rs` | Background `pasta --pcap` tailer, query/response correlation, tmpfs `fallocate` hole punching, and cleanup. |
| `src/dns.rs` | Ethernet/IPv4/IPv6/UDP/TCP DNS query & response (`A`/`AAAA`) parsing, local timestamp formatting, and JSONL audit log read/write. |
| `src/domains.rs` | Domain allowlist/blocklist loader & rule updater (`~/.config/box/domains.txt` / `--domains`), built-in dev registries, and suspicious-domain heuristics. |
| `src/provenance.rs` | Workspace source-code & package-manifest (`Cargo.toml`, `package.json`, `pyproject.toml`, etc.) scanner that identifies what code triggered a DNS lookup. |
| `src/telemetry.rs` | `--traffic` bottom-newest dashboard, `-f/--follow` real-time color-coded terminal stream, `-v/--details`, and `--trace` forensic view. |
| `src/web.rs` & `src/traffic_ui.html` | Zero-dependency local HTTP + SSE server (`--traffic --web`) with live color-coded feed, interactive allow/block editing (`POST /api/domains`), and code-provenance viewer (`GET /api/code`). |

---

## How It Works

### 1. MicroVM Isolation & Hardening

Every box runs inside a KVM microVM rather than a shared-kernel container:

- **Default runtime (`--runtime krun`):** Invokes `podman run --runtime /usr/bin/krun` (`crun-krun` / `libkrun`).
- **Alternative runtime (`--runtime kata`):** Invokes `nerdctl run --runtime io.containerd.kata.v2`.
- **Container & guest hardening:**
  - `--read-only` root filesystem with a `1g`, `nosuid` tmpfs mounted at `/tmp`.
  - `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--user 1000:1000`.
  - Resource limits: `--memory` (default `2g`), `--cpus` (default `2`), `--pids-limit` (default `250`).
  - Workspace is mounted at `/workspace` **read-only (`ro`)** by default (use `--rw` to allow writes), with SELinux relabeling (`:Z`) on `krun`.
  - Refuses to mount `/`, `/home`, `/etc`, `/var`, `/usr`, or your entire `$HOME`.
  - Unless `--ephemeral` is set, mounts a named volume (`--venv`, default `box-venv`) at `/opt/venv` (`CARGO_HOME=/opt/venv/cargo`, `TEXMFVAR=/opt/venv/texmf-var`, `PATH` includes `/opt/venv/python/bin`, `/opt/venv/bin`, and `/opt/venv/cargo/bin`) so package caches persist across runs while `CARGO_TARGET_DIR=/tmp/target` stays ephemeral. For Python presets, interactive shells automatically initialize (if missing) and activate `/opt/venv/python`.
  - Boxes use `--rm` by default (pass `--keep` to retain stopped boxes for `box --list`).

### 2. Network Modes

| Mode | Flag | Behavior |
| --- | --- | --- |
| **Air-gapped** (default) | `--net none` | Passes `--network=none`. No outbound or loopback network access. |
| **Local-only** | `--net local` | Publishes `127.0.0.1:<port>:<port>` to the host browser (e.g. Jupyter) while binding `pasta` outbound to `127.0.0.1` (`-o 127.0.0.1`) and blackholing DNS (`--dns 192.0.2.53`) so all outbound internet TCP/UDP/DNS is genuinely blocked **and** captured via `--pcap` as `BLOCKED` in `--traffic` / `--web`. |
| **Internet (audited)** | `--net internet` | Outbound internet enabled. On rootless `krun`, runs inside `podman-sandbox.slice` (when present) so host nftables rules block LAN access, keeps `--no-map-gw` so host `127.0.0.1` services remain unreachable, and transparently audits all outbound DNS queries. |

### 3. How Rootless DNS Auditing Works

Capturing DNS from a rootless `libkrun` microVM has three constraints:

1. **Unprivileged host:** Rootless processes cannot bind host UDP port `53` (`Permission denied`).
2. **`libkrun` TSI loopback isolation:** `libkrun`'s Transparent Socket Impersonation (TSI) keeps `127.0.0.0/8` traffic inside the guest kernel, so a `pasta -U` (container → host) listener bound to `*%lo:53` cannot be reached from inside the microVM.
3. **Host isolation:** Enabling `pasta --map-gw` would expose host loopback services to the sandbox.

To satisfy all three cleanly, `box` uses `pasta`'s built-in packet capture (`--pcap`) alongside Podman's default DNS forwarder:

```text
[ Guest MicroVM (libkrun TSI) ]
      │  UDP/TCP :53 (default: 169.254.1.1 via Podman --dns-forward,
      │               or any direct IP like 8.8.8.8:53)
      ▼
[ Container netns ──▶ pasta (--no-map-gw --dns-host <upstream> --pcap <file>) ]
      │                                           │
      │ forwards DNS to <upstream>:53             │ writes Ethernet frames to
      ▼                                           │ $XDG_RUNTIME_DIR/box-pcap-<name>-<pid>.pcap
[ Upstream DNS (default 1.1.1.1) ]                ▼
                                      [ Background `box --dns-pcap-file` auditor ]
                                        • tails PCAP frames in real time
                                        • correlates DNS queries + responses (A/AAAA IPs & DNS server)
                                        • appends JSONL to ~/.local/share/box/dns_audit.jsonl
                                        • calls fallocate(PUNCH_HOLE | KEEP_SIZE) every 1 MiB
                                          to reclaim tmpfs RAM during large downloads
                                        • drains & deletes the .pcap file when parent exits
```

Key design details:

- **Cannot be bypassed via `/etc/resolv.conf`:** Because `pasta --pcap` captures all tap-facing traffic leaving the container namespace, even hardcoded DNS queries sent directly to `8.8.8.8:53` or `1.1.1.1:53` are logged.
- **Captures resolved IP addresses:** The auditor parses both outbound queries (`dport 53`, `QR == 0`) and inbound DNS responses (`sport 53`, `QR == 1`), correlating them by `(txid, domain, qtype)` to record resolved IPv4 (`A`) and IPv6 (`AAAA`) addresses alongside the contacted DNS server IP. Unanswered queries are flushed after 750 ms so timeouts/blocks are still logged.
- **SELinux compatibility:** Fedora's `pasta_t` SELinux policy denies creating files in `/tmp` (`tmp_t`), but permits creating and writing files in `$XDG_RUNTIME_DIR` (`/run/user/<uid>`, `user_tmp_t`).
- **Near-zero RAM footprint:** `$XDG_RUNTIME_DIR` is a `tmpfs`. Once 1 MiB of capture data has been parsed, the auditor punches page-aligned holes via `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` so already-processed packets (e.g., large `cargo` or `pip` downloads) are immediately freed from RAM without disturbing `pasta`'s write offset.
- **Lifecycle & cleanup:** Before calling `exec()` into `podman`, `box` passes its own PID (`--dns-proxy-parent-pid`) to the background auditor. Because `exec()` preserves the PID across `systemd-run`/`podman`, the auditor watches `/proc/<pid>`, performs a final drain pass when the sandbox exits, and removes the temporary `.pcap` file.

#### Audit Log Schema

Events are appended as JSON Lines to `${XDG_DATA_HOME:-$HOME/.local/share}/box/dns_audit.jsonl`:

```json
{"ts":1795142870,"box":"box-rust-42870","env":"rust","workspace":"/var/home/alex/Documents/kata-sandbox","cmd":"getent ahosts crates.io","domain":"crates.io","qtype":"A","ips":["151.101.66.137","151.101.2.137"],"dns_server":"169.254.1.1"}
```

### 4. Composable Toolchain Presets & Host Storage Paths

Pass one or more `--preset` values (`alpine`, `bitcoin`, `julia`, `k8s`, `kali`, `latex`, `llama`, `node`, `python`, `rust`):

- **Every preset** builds a locally cached `localhost/box-env:<sorted-presets>` image that includes `ca-certificates`, `curl`, `ping` (`iputils-ping` / `iputils`), and `vim` out of the box:
  - **`julia`**: Official `julia:latest` with **Pluto.jl** pre-installed in `/usr/local/share/julia`, a `pluto` launcher command (binds `0.0.0.0:$PLUTO_PORT`, default `8888`, for `--net local`), and persistent `JULIA_DEPOT_PATH=/opt/venv/julia:/usr/local/share/julia`.
  - **`bitcoin`**: Official Bitcoin Core release binaries (`bitcoin-cli`, `bitcoind`, `bitcoin-tx`, `bitcoin-util`, `bitcoin-wallet`) with persistent `BITCOIN_DATADIR=/opt/venv/bitcoin` (`~/.bitcoin` symlinked automatically).
  - **`k8s`**: Official `kubectl` + `jq` with persistent `KUBECONFIG=/opt/venv/kube/config`.
  - **`llama`**: Fedora base (`docker.io/library/fedora:latest`) matching host Fedora glibc/libstdc++ (`libgomp`, `libcurl`, `python3`, `jq`) — supports **both** running your host-compiled `llama-server` inside the VM (`--llama-bin /path/to/llama.cpp/build/bin`, mounted read-only at `/opt/llama` with `PATH` and `LD_LIBRARY_PATH` configured) **and** talking to a host-running `llama-server` (`--host-port 8080`, reachable inside the VM at `http://host.box.internal:8080` / `$LLAMA_SERVER_URL` / `$OPENAI_BASE_URL`, even while air-gapped from the internet).
  - **`kali`**: `kalilinux/kali-rolling` with lightweight recon/network essentials (`nmap`, `dnsutils`, `netcat-openbsd`, `whois`, `traceroute`, `jq`, `git`) and full Kali `apt` repos.
  - **`latex`**, **`python`**, **`rust`**, **`node`**, **`alpine`**: Existing presets with persistent `/opt/venv` caches (Python venv auto-activated; `luaotfload` & Liberation/DejaVu fonts prebuilt for LaTeX).
- **Multiple Debian presets** (e.g. `--preset latex,python`, `--preset k8s,python`, `--preset kali,k8s`) combine automatically (`kali > julia > latex > rust > node > python/bitcoin/k8s`). `alpine` (musl/apk) and `llama` (Fedora/dnf) cannot be combined with Debian presets.
- **Host storage visibility:**
  - Every launch/attach header prints the exact host paths for `/workspace`, `/opt/venv` (resolved Podman volume mountpoint), `/opt/llama` (if set), and `/tmp` (ephemeral RAM).
  - From the host, run `box --paths` (alias `box --where`) or `box --paths <BOX>` / `box --inspect <BOX>` to inspect where all workspaces, `/opt/venv` data, container images, traffic logs, and PCAPs live on disk.
  - Inside any running VM, run `box-where` or `box-where <file>` to print the exact host filesystem path of a saved file.

### 5. Traffic Dashboard, Real-Time Monitoring & Domain Comparison

- **Color-coded domain classification (`~/.config/box/domains.txt` or `--domains <FILE>`):**
  - **Green (`[OK   ]`):** Matches an allowed domain (exact `=host.tld` or suffix `domain.tld` / `*.domain.tld`). By default combines `~/.config/box/domains.txt` (if present) with built-in common dev registries (`crates.io`, `rust-lang.org`, `pypi.org`, `npmjs.org`, `github.com`, `debian.org`, `ctan.org`, etc.). Passing `--domains <FILE>` compares strictly against that file only.
  - **Yellow (`[NEW  ]`):** Unlisted domain (not in allowlist and not flagged suspicious).
  - **Red (`[ALERT]`):** Matches a blocklisted rule (`!domain` or `-domain` in your domains file) or triggers suspicious-domain heuristics:
    - High-risk TLDs (`.zip`, `.mov`, `.top`, `.xyz`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.onion`)
    - Tunnel / dynamic DNS services (`.nip.io`, `.sslip.io`, `.ngrok.io`, `.trycloudflare.com`)
    - Long first label (`>= 28` chars — potential DNS tunneling/DGA)
    - High-digit entropy first label (`>= 14` chars and `> 50%` digits)
- **Snapshot view (`box --traffic`):**
  - Displays rolling summary windows **oldest → newest** (`LAST 30 DAYS` → `LAST 24 HOURS` → `LAST 1 HOUR` → `LAST 1 MINUTE`) followed by `RECENT DNS ACTIVITY (oldest -> newest)` so the **most recent events are always at the bottom**.
  - Add `-v` / `--details` to print all resolved IPs, DNS server, environment, workspace, and command under each event, or `--limit N` to adjust how many recent events are shown.
- **Live terminal stream (`box --traffic -f` / `--follow`):**
  - Streams new color-coded DNS queries to the bottom of the terminal in real time and hot-reloads `~/.config/box/domains.txt` whenever you edit it.
- **Live browser dashboard (`box --traffic --web`):**
  - Serves a self-contained local dashboard at `http://127.0.0.1:8787` (customizable via `--web-port`) using Server-Sent Events (`/api/stream`), with most recent events auto-scrolling at the bottom and live status/search filtering (`All`, `Blocked`, `Suspicious`, `Unlisted`, `Trusted`).
  - Logs **all outbound traffic** (DNS, HTTPS/TLS SNI, HTTP `Host`, raw TCP, UDP, ICMP) and flags requests blocked by `--net local`, firewall `TCP RST`, `ICMP unreachable`, or DNS timeout/`REFUSED` with a **`BLOCKED`** badge and exact reason.
  - Archives raw Ethernet frames per session under `~/.local/share/box/pcaps/` (up to 50 MiB/session) and exposes **Export PCAP** in the web UI (`GET /api/pcap?file=...`) as well as `box --traffic --export-pcap capture.pcap` for Wireshark analysis.
  - Clicking any row shows network status (`ALLOWED` vs `BLOCKED BY INTERFACE`), resolved IPs, protocol/port, DNS server, box name, environment, workspace, command, **Download PCAP**, **quick `+ Allow` / `Block` / `Remove` buttons** (persisted to `~/.config/box/domains.txt` or `--domains <FILE>`), and a **Code That Generated Traffic** panel scanning the workspace for matching source lines, invoked scripts, or package manifests.
- **Forensic trace (`box --trace <substring>`):**
  - Groups matching queries by `(box, env, workspace, command)` and displays resolved IPs, query types, DNS servers, timestamps, and verdict.
- All views support `--box-filter <substring>` and `--domains <PATH>`.

---

## Building & Testing

If your host has a Rust toolchain and C linker:

```bash
cargo test
cargo build --release
cp target/release/box ~/.local/bin/box
```

On Fedora Atomic hosts without a host C compiler, build inside `docker.io/library/rust:slim` using the cached `box-venv` cargo volume:

```bash
podman run --rm --network=none --userns=keep-id \
  -v "$PWD:/workspace:rw,Z" \
  -v box-venv:/opt/venv:rw,U \
  -e CARGO_HOME=/opt/venv/cargo \
  -w /workspace \
  docker.io/library/rust:slim \
  sh -c "cargo test --offline && cargo build --release --offline"
```

---

## Common Usage Examples

```bash
# Air-gapped Rust shell in current directory (read-only mount)
box --preset rust

# Run a command with audited internet access
box --preset rust --net internet cargo build

# Combine multiple presets with a read-write workspace
box --preset latex,python --rw --net none pdflatex paper.tex

# Local-only dev server exposed on 127.0.0.1:8888
box --preset node --net local --port 8888 npm run dev

# View DNS telemetry (most recent at bottom), live terminal tail, or live browser UI
box --traffic
box --traffic -v
box --traffic -f
box --traffic --web
box --traffic -f --domains ./allowed-domains.txt
box --trace crates.io
box --traffic --box-filter box-rust

# Verify KVM microVM isolation and inspect a specific box's full software stack
box --verify
box --inspect univ                         # Image, Kata vs libkrun proof, OS, installed tools
box --inspect univ -v                      # Same, plus full list of OS & Python packages

# List persisted boxes (created with --keep) and attach/spawn from them
box --list
box --attach my-rust                       # Starts if stopped; spawns a fresh sibling VM if already running
box --attach my-rust --new                 # Always spawn a fresh sibling VM with the same config
box --attach my-rust --same-tty            # Reconnect directly to a detached running process's TTY
box --attach my-rust --mount-cwd --rw      # Mount current directory read-write at /workspace
```
