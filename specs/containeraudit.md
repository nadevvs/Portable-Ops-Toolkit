# containeraudit

## Purpose

Audit local Docker or Podman runtime posture.

## Inputs

- `docker ps` / `podman ps`
- `docker inspect` / `podman inspect`

## Output

- Container inventory and posture findings

## Safety

Read-only. Does not pull, stop, start, restart, exec into, or modify containers.

## Example

```bash
python3 containeraudit.py --json --no-color
```
