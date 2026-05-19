# ARPGuard

ARPGuard is a Linux-first command-line tool that detects suspicious ARP behavior and possible ARP spoofing on your local network.

It combines:
- **passive ARP monitoring** (sniffing ARP traffic), and
- **active verification** (sending ARP queries to confirm mappings).

## Features

- Automatic detection of:
  - active network interface
  - default gateway IP
- Gateway baseline learning (trusts a stable gateway MAC before normal monitoring)
- Detection of:
  - MAC changes for known IPs
  - multiple MACs claiming the same IP
- Active ARP verification to reduce false positives
- Warning/Critical alert levels with structured event output
- Optional text and JSONL logging
- Auto-reset and re-learning when network/interface/gateway changes
- Advanced **pro** mode to tune learning and verification behavior

## Requirements

- Linux (uses `ip` command and ARP sniffing)
- Python **3.8+**
- Root privileges (or `sudo`) for packet sniffing/sending

## Installation

From the repository root:

```bash
python3 -m pip install .
```

Or install in editable/development mode:

```bash
python3 -m pip install -e .
```

If you prefer requirements file installation:

```bash
python3 -m pip install -r requirements.txt
```

## Quick Start

Run with auto-detected interface and gateway:

```bash
sudo arpguard
```

Typical startup flow:
1. Detect interface, local IP/MAC, and gateway.
2. Learn a trusted gateway baseline MAC.
3. Start continuous monitoring and verification on suspicious events.

Stop with `Ctrl + C`.

## Usage

### Standard mode

```bash
sudo arpguard [options]
```

Options:
- `--iface <name>`: set interface (otherwise auto-detected)
- `--gateway <ip>`: override auto-detected gateway
- `-v, --verbose`: print ARP packet-level activity
- `--quiet`: show only WARN/CRITICAL events
- `--logfile <path>`: write human-readable logs
- `--json-logfile <path>`: write JSON event logs (one JSON object per line)

### Pro mode

```bash
sudo arpguard pro [options]
```

Additional pro options:
- `--learn-seconds <int>` (default: `60`)
- `--window-seconds <int>` (default: `30`)
- `--verify-count <int>` (default: `5`)
- `--verify-timeout <float>` (default: `1.0`)
- `--verify-new` (actively verify every newly seen host; noisier)

## How Detection Works (High Level)

1. **Learning phase**  
   ARPGuard observes and verifies the gateway mapping before trusting it.

2. **Monitoring phase**  
   ARP packets are tracked per IP/MAC claim.

3. **Suspicion triggers**  
   ARPGuard flags events when:
   - known IP suddenly reports a different MAC
   - multiple MACs claim the same IP in the active window
   - (`pro --verify-new`) new hosts are immediately verified

4. **Active verification**  
   ARP probes are sent to confirm whether mapping is stable or conflicting.

5. **Alerting**  
   - `WARN`: suspicious event or insufficient verification evidence
   - `CRITICAL`: likely spoofing / baseline conflict
   - `SAFE`: stable trusted gateway baseline established

## Logging

Use one or both:

- `--logfile /path/to/arpguard.log`  
  Human-readable timestamped log lines
- `--json-logfile /path/to/arpguard.jsonl`  
  Machine-readable JSON events (JSONL format)

## Troubleshooting

- **Startup failed / cannot auto-detect interface or gateway**
  - Ensure `ip route show default` works on your system.
  - Provide explicit values with `--iface` and/or `--gateway`.

- **Permission errors / no packets captured**
  - Run with `sudo` (raw packet operations require elevated privileges).

- **No baseline established**
  - ARP traffic may be low at that moment; ARPGuard retries baseline learning automatically.

## Development

Run tests:

```bash
python -m pytest tests/
```
