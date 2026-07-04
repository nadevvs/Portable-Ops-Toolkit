# logtriage

## Purpose

Summarize recent logs for authentication, service, kernel, and access-control indicators.

## Inputs

- `journalctl`
- Fallback files under `/var/log`

## Output

- Counts, examples, and severity findings

## Safety

Read-only. Redacts common secret-looking values.

## Example

```bash
python3 logtriage.py --lines 500
```
