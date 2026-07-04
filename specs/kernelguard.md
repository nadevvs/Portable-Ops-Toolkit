# kernelguard

## Purpose

Audit kernel and sysctl hardening posture from local `/proc/sys` values.

## Inputs

- `/proc/sys/...` hardening values
- `/proc/modules`

## Output

- Sysctl values, loaded-module sample, findings, warnings, and overall status

## Safety

Read-only. Does not change sysctl values or load/unload modules.

## Example

```bash
python3 kernelguard.py --json --no-color
```
