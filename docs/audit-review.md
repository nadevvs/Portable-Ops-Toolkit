# Audit Review

Date: 2026-06-29

## Scope

Reviewed the original ops tools, the first security/DFIR batch, the second host
posture batch, and the `opsrun` combiner.

## Checks Performed

```bash
python3 -m unittest discover
python3 -m py_compile *.py common/*.py
for f in *.py; do python3 "$f" --help >/dev/null || exit 1; done
```

Static review commands:

```bash
rg "shell=True|subprocess\.run|subprocess\.Popen|os\.system|eval\(|exec\(|pickle|requests|urllib|socket\.create_connection" *.py common tests
rg "write_text|open\(|mkdir|ensure_state_dir|NamedTemporaryFile|mkdtemp" *.py common tests
rg "systemctl (restart|stop|start|enable|disable)|iptables -A|iptables -D|nft add|nft delete|ufw allow|ufw deny|chmod |chown |rm -rf|shutil\.rmtree|unlink\(|remove\(" *.py common tests
```

## Results

- Unit tests pass.
- Python byte-compilation passes.
- Every CLI responds to `--help`.
- Direct subprocess execution is centralized in `common/cmd.py`.
- No `shell=True`, `os.system`, network client library usage, package install,
  service modification, firewall modification, permission change, or destructive
  file operation was found in tool code.
- Stateful writes are limited to toolkit state paths for `blackbox`,
  `permdrift`, `evidencetrail`, and `opsrun`.
- Test writes are confined to temporary directories.

## Expected Limitations

- Many collectors are Linux-first and return partial results on macOS or
  restricted sandboxes.
- Some Linux data sources require elevated permissions for full visibility.
- `iocscan` is exact-match only and intentionally does not implement YARA.
- `pkgledger` does not perform vulnerability lookups because internet access is
  intentionally avoided.
- `evidencetrail` records metadata and hashes; it does not copy evidence content
  or provide legal chain-of-custody workflow controls.
- `opsrun` skips targeted/stateful tools by default because tools such as
  `svcdep`, `permdrift`, `blackbox`, and `evidencetrail` need explicit targets
  or subcommands.
