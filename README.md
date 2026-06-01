# Portable Ops Toolkit

Lightweight Python command-line diagnostics for Linux servers and workstations.

The toolkit is designed to run directly from a directory or USB drive without
installation. Tools should prefer the Python standard library, avoid network
access, and avoid changing the host system. Any local history or cache data must
be written only under the path selected with `--state`.

## Planned Tools

- `svcdep` - service dependency checker
- `croninv` - cron and systemd timer inventory
- `permdrift` - file permission drift checker
- `sshexpose` - SSH exposure auditor
- `blackbox` - server black box recorder
- `serverdoctor` - one-command server overview

## `svcdep`

Diagnoses one systemd service by collecting basic unit status, related
processes, listening ports, direct dependencies, unit file metadata, and recent
notable journal lines.

Examples:

```bash
python3 svcdep.py nginx
python3 svcdep.py ssh --json
python3 svcdep.py postgresql --logs 50 --state /media/usb/ops-state
```

Limitations:

- Focuses on systemd-based Linux systems.
- Uses best-effort process and port matching.
- Some `ss -p` and journal details may require elevated permissions.
- Does not restart, enable, disable, edit, or otherwise modify services.

## `croninv`

Inventories system cron files, periodic cron directories, optional current-user
crontab entries, and systemd timers.

```bash
python3 croninv.py
python3 croninv.py --json
python3 croninv.py --include-users --suspicious
```

## `permdrift`

Checks file metadata against a simple pipe-delimited baseline. It never changes
permissions; it only reports drift. An example baseline is available at
`configs/permdrift.example.conf`.

```bash
python3 permdrift.py init permdrift.conf
python3 permdrift.py check permdrift.conf
python3 permdrift.py snapshot permdrift.conf --state ./ops_state
python3 permdrift.py diff permdrift.conf --state ./ops_state
```

## `sshexpose`

Audits local OpenSSH service status, listeners, important config settings,
recent authentication logs, optional authorized key inventories, and Fail2ban
status if available.

```bash
python3 sshexpose.py
python3 sshexpose.py --json
python3 sshexpose.py --users --logs 200
```

## `blackbox`

Records compact JSONL snapshots under `STATE/blackbox/`. It is intended to be
called manually, from cron, or from a user-managed systemd timer.

```bash
python3 blackbox.py record --state ./ops_state
python3 blackbox.py summary --state ./ops_state
python3 blackbox.py tail --state ./ops_state
python3 blackbox.py prune --state ./ops_state --days 2
```

## `serverdoctor`

Runs a quick first-pass health overview and recommends focused follow-up tools.

```bash
python3 serverdoctor.py
python3 serverdoctor.py --json
python3 serverdoctor.py --checks system,disk,memory,network,security,logs
```

## Development

This project targets Python 3.8+ and intentionally avoids runtime package
dependencies.

Run tests with:

```bash
python3 -m unittest discover
```

## Portability Rules

- Do not require root for basic operation.
- Do not install agents or packages.
- Do not modify system services, firewall rules, permissions, logs, or SSH
  configuration.
- Call external commands only through a safe wrapper with timeouts.
- Handle missing commands, permission errors, and non-zero exits gracefully.
- Disable ANSI color automatically when stdout is not a TTY.
