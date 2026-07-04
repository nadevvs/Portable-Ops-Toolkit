# procaudit

## Purpose

Find suspicious running-process leads for DevSecOps and incident response.

## Inputs

- `ps` process listing
- Optional `/proc/PID/exe`, `/proc/PID/cwd`, and `/proc/PID/status` with `--deep`

## Output

- Human terminal summary by default
- JSON with `tool`, `overall`, `findings`, and `warnings` when `--json` is used

## Safety

Read-only. Does not kill, renice, trace, or modify processes.

## Example

```bash
python3 procaudit.py --deep --json --no-color
```
