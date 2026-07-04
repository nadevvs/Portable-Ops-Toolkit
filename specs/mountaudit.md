# mountaudit

## Purpose

Review mount and fstab security options.

## Inputs

- `/proc/self/mountinfo`
- `/etc/fstab`

## Output

- Parsed mounts, parsed fstab entries, findings, and overall status

## Safety

Read-only. Does not mount, unmount, remount, or edit fstab.

## Example

```bash
python3 mountaudit.py --json --no-color
```
