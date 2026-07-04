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
- `procaudit` - process investigation lead finder
- `netaudit` - network listener and session auditor
- `logtriage` - recent log triage for IR
- `iocscan` - offline IOC scanner
- `persistwatch` - Linux persistence inventory
- `pkgledger` - offline package inventory and change ledger
- `containeraudit` - local Docker/Podman posture audit
- `evidencetrail` - evidence manifest and hash verifier
- `kernelguard` - kernel/sysctl hardening audit
- `fireaudit` - firewall posture audit
- `suidscan` - SUID/SGID and writable-path scan
- `auditpol` - auditd/auditctl policy review
- `accttrail` - login and account activity summary
- `mountaudit` - mount/fstab option audit
- `envleak` - secret-like key exposure scan
- `certwatch` - local certificate expiry inventory
- `webaudit` - nginx/apache config lead finder
- `cloudaudit` - cloud-init and metadata posture audit
- `opsrun` - local profile runner and JSON bundle collector

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

## Security and DFIR Tools

These tools follow the same portability rules as the original ops tools: no
network access, no package installs, no host configuration changes, and local
state only under `--state`.

All security tools support:

```bash
python3 TOOL.py --help
python3 TOOL.py --json --no-color
python3 TOOL.py --state /media/usb/ops-state
```

The JSON shape is intentionally similar across tools:

```json
{
  "tool": "name",
  "overall": "OK|INFO|WARN|CRITICAL",
  "findings": [],
  "warnings": []
}
```

That makes the tools easy to combine from shell scripts:

```bash
for tool in procaudit netaudit logtriage persistwatch pkgledger containeraudit; do
  python3 "$tool.py" --json --no-color --state ./ops_state > "./ops_state/$tool.json"
done
```

### `procaudit`

Reviews running processes for incident-response leads such as deleted
executables, temporary execution paths, shell download patterns, decode/decrypt
patterns, and very long command lines.

```bash
python3 procaudit.py
python3 procaudit.py --deep --json
```

Limitations: `/proc` metadata is Linux-specific and may require permissions.
The tool reports partial results if process listing is restricted.

### `netaudit`

Reviews local listeners and flags risky services exposed on all interfaces, such
as Redis, databases, Docker API, NFS, SMB, Elasticsearch, and Memcached.

```bash
python3 netaudit.py
python3 netaudit.py --json --no-color
```

Limitations: depends on `ss` for best results. It does not change firewall
rules, routes, or listening services.

### `logtriage`

Summarizes recent journal or syslog/auth logs for authentication failures,
successful logins, sudo activity, OOM kills, segfaults, access-control denials,
and service failure wording.

```bash
python3 logtriage.py --lines 500
python3 logtriage.py --json
```

Limitations: log visibility depends on local permissions and host logging
configuration.

### `iocscan`

Scans local files for simple offline indicators: `sha256:`, `path:`,
`domain:`, `ip:`, and `text:` entries. It has file and byte limits so scans are
bounded on production hosts.

```bash
python3 iocscan.py --iocs configs/iocscan.example.ioc --paths /etc,/tmp
python3 iocscan.py --iocs case.ioc --paths /srv/app --max-files 5000 --json
```

Limitations: this is a lightweight exact-match scanner, not a YARA engine or
malware sandbox.

### `persistwatch`

Inventories common Linux persistence locations: systemd units, init scripts,
cron drop-ins, shell profiles, `rc.local`, and `ld.so.preload`. It flags
world-writable entries and suspicious download/temp-path/encoded-command
patterns.

```bash
python3 persistwatch.py
python3 persistwatch.py --paths /opt/app/startup.sh --json
```

Limitations: it is a lead finder. It does not disable, delete, or edit
persistence mechanisms.

### `pkgledger`

Builds an offline package inventory from `dpkg`, `rpm`, or `apk` when available,
then summarizes local package change logs. It flags legacy high-risk network
packages and security-relevant removal events.

```bash
python3 pkgledger.py
python3 pkgledger.py --limit 100 --json
```

Limitations: no vulnerability lookup is performed because the toolkit avoids
internet access.

### `containeraudit`

Uses local Docker or Podman CLIs if available to list running containers and
inspect common posture issues: privileged mode, host networking, host PID
namespace, all-interface port publishing, root/default users, and host-root bind
mounts.

```bash
python3 containeraudit.py
python3 containeraudit.py --json --no-color
```

Limitations: only running containers visible to the current user are inspected.
It does not stop, restart, pull, or modify containers.

### `evidencetrail`

Creates a case manifest under `STATE/evidencetrail/CASE/manifest.json` with file
metadata and SHA-256 hashes. Later verification checks whether hashed evidence
changed.

```bash
python3 evidencetrail.py record --case web1 --paths /etc/ssh/sshd_config,/var/log/auth.log --state ./ops_state
python3 evidencetrail.py verify --case web1 --state ./ops_state --json
```

Limitations: this is a practical integrity manifest, not a full legal evidence
management system. It does not copy evidence content by default.

## Research Basis

The security and DFIR additions are based on common local evidence sources and
incident-response needs described by NIST SP 800-61 Rev. 3, NIST SP 800-86, and
the MITRE ATT&CK Linux matrix. See `docs/security-research.md` for the mapping.

## Additional Security Tools

The second security batch extends host posture, account, web, cloud, and
certificate checks. These tools follow the same rules: read-only host access,
standard library Python, `--json`, `--no-color`, and `--state`.

```bash
python3 kernelguard.py --json
python3 fireaudit.py --json
python3 suidscan.py --paths /usr/bin,/tmp --max-entries 10000
python3 auditpol.py
python3 accttrail.py --limit 100
python3 mountaudit.py --json
python3 envleak.py --paths /etc/default,/srv/app --json
python3 certwatch.py --paths /etc/ssl/certs,/etc/letsencrypt/live
python3 webaudit.py --paths /etc/nginx,/etc/apache2
python3 cloudaudit.py --json --no-color
python3 opsrun.py --profile posture --save --json --state ./ops_state
```

Purposes:

- `kernelguard` reads `/proc/sys` hardening values and loaded modules.
- `fireaudit` checks local `ufw`, `iptables`, and `nft` posture.
- `suidscan` finds SUID/SGID files and world-writable directories.
- `auditpol` reviews audit status, syscall/watch coverage, and auditd config.
- `accttrail` summarizes `last`, `lastlog`, and `/etc/passwd` leads.
- `mountaudit` reviews sensitive mount options such as `nosuid` and `noexec`.
- `envleak` reports secret-like key names without printing values.
- `certwatch` decodes local PEM certificates and flags expiry windows.
- `webaudit` parses local nginx/apache config directives for exposure leads.
- `cloudaudit` reviews cloud-init files and metadata-IP references.
- `opsrun` runs selected local tools and optionally saves a consolidated bundle.

Detailed task specs for all security tools live under `specs/`.

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
