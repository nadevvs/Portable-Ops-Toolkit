# Task: `blackbox` — Server Black Box Recorder

## Goal

Create a lightweight Python CLI tool that records small periodic snapshots of server state.

It should help answer: "What was happening before the server crashed, slowed down, or lost network?"

The tool should work without installing an agent. It can be run manually, from cron, or from a systemd timer created by the user separately.

Example:

```bash
python3 blackbox.py record --state /media/usb/ops-state
python3 blackbox.py summary --state /media/usb/ops-state
python3 blackbox.py tail --state /media/usb/ops-state
```

## Main questions this tool answers

- What was load/memory/disk state over time?
- Which processes were using CPU/memory?
- What services failed recently?
- What network ports/connections existed?
- Did the system reboot?
- Were there OOM kills or kernel errors?
- What changed shortly before a problem?

## Scope

The tool records compact JSONL snapshots.

It should not run as a daemon by itself in the first version. Instead, it provides a `record` command that can be called repeatedly.

This makes it portable and simple.

## CLI

Required subcommands:

```bash
python3 blackbox.py record --state PATH
python3 blackbox.py summary --state PATH
python3 blackbox.py tail --state PATH
python3 blackbox.py prune --state PATH --days 2
```

Required flags:

```bash
--json
--no-color
--state PATH
```

Optional:

```bash
python3 blackbox.py export --state PATH --out report.json
python3 blackbox.py inspect --state PATH --since "1 hour"
```

## State layout

Store under:

```text
STATE/
  blackbox/
    snapshots.jsonl
    metadata.json
```

Each line in `snapshots.jsonl` is one JSON object.

Do not store huge logs by default. Keep snapshots compact.

## Snapshot contents

Each snapshot should include:

### 1. Time and host identity

- timestamp ISO 8601 UTC/local
- hostname
- uptime seconds
- boot ID if available from `/proc/sys/kernel/random/boot_id`

### 2. Load and CPU

Read:

```text
/proc/loadavg
```

Store:

- load1
- load5
- load15
- running processes count if available

### 3. Memory

Read:

```text
/proc/meminfo
```

Store:

- MemTotal
- MemAvailable
- SwapTotal
- SwapFree
- calculated memory used percent
- calculated swap used percent

### 4. Disk

Use:

```bash
df -P
```

Store for real filesystems:

- mount
- filesystem
- size
- used
- available
- used percent

Skip noisy pseudo filesystems if needed.

### 5. Top processes

Use:

```bash
ps -eo pid,ppid,user,comm,%cpu,%mem,rss,args --sort=-%cpu
```

Store top 5 by CPU and top 5 by memory.

Keep args truncated to avoid huge files.

### 6. Services

If systemd available:

```bash
systemctl --failed --no-pager
```

Store failed units.

Optional:
- count running services
- recent restart indicators if cheap

### 7. Network

Use:

```bash
ss -tuna
```

Store summary counts:

- listening TCP sockets
- established TCP connections
- UDP sockets
- top remote IPs if available

Do not store every connection by default unless `--deep` is added.

### 8. Kernel warnings

Best effort:

```bash
journalctl -k -n 30 --no-pager
```

or:

```bash
dmesg --ctime --level=err,warn
```

Store only recent count and last few notable lines.

Look for:

- OOM
- killed process
- I/O error
- thermal
- segfault
- blocked for more than
- filesystem error

## Human output

For `record`:

```text
blackbox: snapshot recorded
time: 2026-06-01T20:15:00
load: 0.21 0.18 0.12
memory: 42% used
disk: / 61% used
failed services: 0
notable kernel lines: 0
```

For `summary`:

```text
blackbox: summary from 144 snapshots

Time range: 2026-06-01 10:00 -> 2026-06-01 20:00
Max load1: 4.92 at 18:31
Max memory used: 91% at 18:32
Max disk / used: 82%
Reboots detected: 1
Failed services seen:
  nginx.service first_seen=18:33 last_seen=18:40
Notable events:
  OOM kill detected at 18:32
```

For `tail`:

Show the last 5 snapshots in compact form.

## JSON output

`record --json` should print the snapshot object.

`summary --json` should print computed summary.

## Pruning

`prune --days N` should remove snapshots older than N days.

Implementation can rewrite `snapshots.jsonl` safely:

- read all
- filter
- write temp file
- rename

Handle corrupt lines by skipping with warning.

## Flash-drive usage

The tool should support storing state on a USB drive:

```bash
python3 /media/usb/ops-toolkit/blackbox.py record --state /media/usb/ops-state
```

If state path is not writable, show a clear error.

## Optional cron usage example

The generated README may show:

```cron
* * * * * python3 /media/usb/ops-toolkit/blackbox.py record --state /media/usb/ops-state >/dev/null 2>&1
```

But the tool should not install this automatically.

## Implementation hints

Use small functions:

- `read_loadavg()`
- `read_meminfo()`
- `collect_disk()`
- `collect_top_processes()`
- `collect_failed_services()`
- `collect_network_summary()`
- `collect_kernel_notables()`
- `write_snapshot(state, snapshot)`
- `read_snapshots(state)`
- `summarize_snapshots(snapshots)`

Keep snapshots reasonably small.

Use JSON Lines because it is easy to append and recover from partial corruption.

## Edge cases

Handle:

- missing `systemctl`
- missing `journalctl`
- permission denied for kernel logs
- full or read-only state path
- corrupt JSONL line
- huge command output
- reboot between snapshots
- USB drive removed

## Non-goals

Do not:

- run permanently as a daemon
- install systemd timer
- upload metrics
- implement alerting
- collect full logs
- store secrets or environment variables

## Suggested tests

1. Parse `/proc/meminfo` sample.
2. Parse `df -P` sample.
3. Parse `ps` sample.
4. Write and read JSONL snapshots.
5. Summary detects max memory/load.
6. Summary detects reboot by changed boot ID.

## Definition of done

The tool is done when:

- `record` appends one compact JSON snapshot
- `summary` produces useful historical summary
- `tail` shows recent snapshots
- `prune` removes old snapshots
- it supports portable `--state`
- it gracefully skips unavailable data
