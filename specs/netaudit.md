# netaudit

## Purpose

Identify exposed listeners and risky services bound to all interfaces.

## Inputs

- `ss -tulpna`

## Output

- Listener table and findings
- JSON suitable for scripts

## Safety

Read-only. Does not modify firewall, routes, sockets, or services.

## Example

```bash
python3 netaudit.py --json --no-color
```
