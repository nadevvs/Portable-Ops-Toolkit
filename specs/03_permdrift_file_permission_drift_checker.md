# Task: `permdrift` — File Permission Drift Checker

## Goal

Create a lightweight Python CLI tool that checks important files/directories against an expected permission baseline.

This is useful for detecting accidental or suspicious permission changes on Linux servers.

Example:

```bash
python3 permdrift.py check permdrift.yml
python3 permdrift.py init permdrift.yml
python3 permdrift.py check permdrift.yml --json
```

## Main questions this tool answers

- Are important files still owned by the expected user/group?
- Are permissions still safe?
- Did a file become world-writable?
- Did an important file disappear?
- Did a sensitive file become readable by too many users?
- Did the file type change?

## Scope

Check files and directories specified in a config file.

The tool should not change permissions. It only reports drift.

## Config format

Prefer simple YAML-like format, but avoid external YAML dependency if possible.

Option A: implement a tiny custom line-based config.

Example:

```text
# path | mode | owner | group | type | note
/etc/ssh/sshd_config | 600 | root | root | file | SSH daemon config
/etc/sudoers | 440 | root | root | file | sudo config
/root/.ssh | 700 | root | root | dir | root SSH directory
/root/.ssh/authorized_keys | 600 | root | root | file | root authorized keys
/var/www/app/.env | 600 | deploy | deploy | file | app secrets
```

This is easier than YAML and avoids dependencies.

Also support comments with `#`.

## CLI

Required:

```bash
python3 permdrift.py check CONFIG
python3 permdrift.py init CONFIG
python3 permdrift.py check CONFIG --json
python3 permdrift.py check CONFIG --no-color
python3 permdrift.py check CONFIG --state PATH
```

Optional:

```bash
python3 permdrift.py snapshot CONFIG
python3 permdrift.py diff CONFIG
```

### `check`

Compares current file metadata with expected config.

### `init`

Creates an example config file if it does not exist.

### `snapshot`

Stores current metadata for all configured paths under `--state`.

### `diff`

Compares current metadata with last snapshot.

## Checks

For each path check:

- exists
- file type: file, dir, symlink, socket, device, other
- mode, for example `600`, `644`, `755`
- owner username
- group name
- world-writable bit
- setuid/setgid bits
- symlink target if symlink
- modified time
- inode optionally

## Severity levels

Suggested:

### OK

Everything matches.

### WARN

- mode differs but not obviously dangerous
- owner/group differs but still non-root expected use case
- file missing but marked optional
- modified time changed since snapshot

### CRITICAL

- world-writable sensitive file
- private key readable by group/others
- `/etc/sudoers` not owned by root
- SSH config owned by non-root
- setuid bit unexpectedly present
- file type changed from file to symlink
- expected file missing and not optional

Keep rules simple and transparent.

## Optional config fields

Support optional entries like:

```text
/etc/nginx/sites-enabled/example | 644 | root | root | file | nginx config | optional
```

If `optional` is present, missing file is warning instead of critical.

## Output format

### Human output

Suggested:

```text
permdrift: checking 5 paths

[OK] /etc/ssh/sshd_config
     mode=600 owner=root group=root type=file

[CRITICAL] /var/www/app/.env
     expected mode=600 owner=deploy group=deploy
     actual   mode=644 owner=deploy group=deploy
     reason: sensitive-looking file is readable by group/others

[WARN] /etc/nginx/sites-enabled/example
     reason: file missing, marked optional
```

### JSON output

Suggested:

```json
{
  "checked": 5,
  "ok": 3,
  "warnings": 1,
  "critical": 1,
  "results": []
}
```

## Default example baseline

`init` should generate a reasonable sample config with comments, not a system-specific hardcoded baseline.

Example entries:

```text
/etc/ssh/sshd_config | 600 | root | root | file | SSH daemon config
/etc/sudoers | 440 | root | root | file | sudoers
/etc/passwd | 644 | root | root | file | user database
/etc/shadow | 640 | root | shadow | file | password hashes
```

But note that `/etc/shadow` group may vary by distro. Mention that user should adjust.

## Implementation hints

Use:

- `os.stat`
- `os.lstat`
- `stat` module
- `pwd.getpwuid`
- `grp.getgrgid`
- `pathlib.Path`

Important:
- Use `lstat` first so symlinks can be detected.
- Do not follow symlinks unless explicitly needed.
- Format mode with `oct(mode & 0o7777)` or custom function.

Suggested pure functions:

- `parse_config(text)`
- `get_file_metadata(path)`
- `compare_expected_actual(expected, actual)`
- `classify_issue(expected, actual)`

## Edge cases

Handle:

- path does not exist
- permission denied
- unknown UID/GID
- symlink loops
- path contains spaces
- malformed config line
- comments and blank lines

Because paths may contain spaces, splitting by `|` is better than splitting by whitespace.

## Non-goals

Do not:

- chmod files
- chown files
- delete files
- follow symlinks blindly
- scan the whole filesystem by default

## Suggested tests

1. Parse a valid config line.
2. Parse comments and blank lines.
3. Detect mode mismatch.
4. Detect owner mismatch.
5. Detect world-writable critical issue.
6. Missing optional file becomes warning.

## Definition of done

The tool is done when:

- it reads a config file
- checks file metadata
- reports OK/WARN/CRITICAL
- supports JSON
- can create example config
- never changes system permissions
