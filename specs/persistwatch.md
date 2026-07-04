# persistwatch

## Purpose

Inventory common Linux persistence locations and flag suspicious entries.

## Inputs

- systemd unit files
- init and cron drop-ins
- shell profiles
- `rc.local`
- `ld.so.preload`

## Output

- Persistence inventory and findings

## Safety

Read-only. Does not disable, delete, or edit persistence entries.

## Example

```bash
python3 persistwatch.py --paths /opt/app/startup.sh --json
```
