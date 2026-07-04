# Security and DFIR Tooling Notes

This repo stays deliberately small: standard library Python, safe command
wrappers, local-only state, and read-only host interaction except where a command
explicitly records toolkit state.

## Sources

- NIST SP 800-61 Rev. 3, "Incident Response Recommendations and Considerations
  for Cybersecurity Risk Management: A CSF 2.0 Community Profile" (April 2025).
  This shaped the split between preparation, detection, response, and recovery
  support. Source: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-86, "Guide to Integrating Forensic Techniques into Incident
  Response" (August 2006). This supports the focus on file, OS, network, and
  application log sources, plus careful evidence hashing. Source:
  https://csrc.nist.gov/pubs/sp/800/86/final
- MITRE ATT&CK Enterprise Linux matrix. This shaped checks around scheduled
  jobs, systemd services, SSH authorized keys, shell startup files, dynamic
  linker hijacking, command interpreters, and network exposure. Source:
  https://attack.mitre.org/matrices/enterprise/linux/

## Tool Mapping

| Tool | Purpose | Evidence sources | Main output |
| --- | --- | --- | --- |
| `procaudit` | Find process investigation leads | `ps`, optional `/proc` | Suspicious process findings |
| `netaudit` | Find exposed listeners | `ss` | Listener exposure findings |
| `logtriage` | Summarize recent security logs | `journalctl`, auth/syslog files | Counts, examples, findings |
| `iocscan` | Match simple offline IOCs | Local files | IOC matches |
| `persistwatch` | Inventory persistence locations | systemd, init, cron, shell profiles | Persistence findings |
| `pkgledger` | Inventory packages and local changes | `dpkg`, `rpm`, `apk`, apt logs | Package list and change ledger |
| `containeraudit` | Check local container posture | Docker/Podman CLI | Container risk findings |
| `evidencetrail` | Hash and verify evidence paths | Selected local files | Manifest and verification report |
| `kernelguard` | Check kernel/sysctl posture | `/proc/sys`, `/proc/modules` | Hardening findings |
| `fireaudit` | Check firewall posture | `ufw`, `iptables`, `nft` | Firewall findings |
| `suidscan` | Find risky file permission leads | Selected filesystem roots | SUID/writable path findings |
| `auditpol` | Review audit policy | `auditctl`, audit config files | Audit coverage findings |
| `accttrail` | Summarize account activity | `last`, `lastlog`, `/etc/passwd` | Login/account findings |
| `mountaudit` | Review mount options | `/proc/self/mountinfo`, `/etc/fstab` | Mount option findings |
| `envleak` | Find secret-like key names | Config/env files | Redacted exposure findings |
| `certwatch` | Check certificate expiry | Local PEM/CRT/CER files | Expiry findings |
| `webaudit` | Review web config leads | nginx/apache config files | Exposure/logging findings |
| `cloudaudit` | Review cloud-init metadata leads | `/etc/cloud`, `/var/lib/cloud`, routes | Cloud-init findings |
| `opsrun` | Combine toolkit output | Local toolkit JSON CLIs | Consolidated bundle |

## Composition Model

Each new tool emits JSON with `tool`, `overall`, `findings`, and `warnings`
where practical. This lets operators run tools independently from a USB drive or
combine them through simple shell loops without installing an agent.

Recommended bundle for a first-pass incident snapshot:

```bash
run_dir="./ops_state/run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$run_dir"
for tool in procaudit netaudit logtriage persistwatch pkgledger containeraudit; do
  python3 "$tool.py" --json --no-color --state ./ops_state > "$run_dir/$tool.json"
done
python3 evidencetrail.py record --case first-pass --paths /etc/ssh/sshd_config,/etc/passwd --state ./ops_state
```

Expanded host posture bundle:

```bash
for tool in kernelguard fireaudit suidscan auditpol accttrail mountaudit envleak certwatch webaudit cloudaudit; do
  python3 "$tool.py" --json --no-color --state ./ops_state > "$run_dir/$tool.json"
done
python3 opsrun.py --profile posture --save --json --state ./ops_state > "$run_dir/opsrun.json"
```

## Safety Review Checklist

- No tool modifies firewall rules, services, SSH configuration, packages, file
  permissions, or logs.
- External commands are called through `common.cmd.run_cmd`, without
  `shell=True`.
- Stateful writes are limited to `--state`, currently by `evidencetrail` and the
  existing stateful tools.
- Secrets in process arguments and logs pass through existing redaction helpers.
- Tests use parser samples and temporary directories instead of host-specific
  systemd, root, Docker, or log state.
