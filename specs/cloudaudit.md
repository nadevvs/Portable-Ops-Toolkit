# cloudaudit

## Purpose

Audit local cloud-init files and metadata references for incident-response leads.

## Inputs

- `/etc/cloud`
- `/var/lib/cloud`
- `/proc/net/route`

## Output

- Cloud-init sensitive directive references, metadata IP references, route hints, and findings

## Safety

Read-only. Does not query cloud metadata services or change cloud-init state.

## Example

```bash
python3 cloudaudit.py --json --no-color
```
