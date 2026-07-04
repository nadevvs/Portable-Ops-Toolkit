import tempfile
import unittest
from pathlib import Path

from accttrail import classify_findings as classify_account_findings
from accttrail import parse_last, parse_lastlog, parse_passwd
from auditpol import classify_findings as classify_audit_findings
from auditpol import parse_audit_rules, parse_auditd_conf
from certwatch import classify_findings as classify_cert_findings
from certwatch import parse_cert_date
from cloudaudit import classify_findings as classify_cloud_findings
from cloudaudit import parse_routes, scan_cloud_text
from envleak import scan_text
from fireaudit import classify_findings as classify_fire_findings
from fireaudit import parse_iptables_policy, parse_ufw_status
from kernelguard import classify_sysctls, parse_modules
from mountaudit import classify_findings as classify_mount_findings
from mountaudit import parse_fstab, parse_mountinfo
from opsrun import select_tools, summarize_reports
from suidscan import classify_entries
from webaudit import classify_findings as classify_web_findings
from webaudit import parse_web_config


class KernelguardTests(unittest.TestCase):
    def test_parse_modules(self):
        modules = parse_modules("usb_storage 77824 0 - Live 0x0\n")

        self.assertEqual(modules[0]["name"], "usb_storage")

    def test_classify_sysctl_warns_on_weak_aslr(self):
        findings = classify_sysctls(
            {"kernel.randomize_va_space": {"exists": True, "value": "0"}},
            [],
        )

        self.assertEqual(findings[0]["severity"], "WARN")


class FireauditTests(unittest.TestCase):
    def test_parse_ufw_status(self):
        parsed = parse_ufw_status("Status: active\n22/tcp ALLOW IN Anywhere\n")

        self.assertTrue(parsed["enabled"])
        self.assertEqual(len(parsed["rules"]), 1)

    def test_parse_iptables_policy(self):
        policies = parse_iptables_policy("Chain INPUT (policy ACCEPT)\n")

        self.assertEqual(policies[0]["policy"], "ACCEPT")

    def test_classify_missing_firewall_warns(self):
        findings = classify_fire_findings({"inactive": True}, [], "")

        self.assertEqual(findings[0]["severity"], "WARN")


class SuidscanTests(unittest.TestCase):
    def test_classify_tmp_suid_is_critical(self):
        findings = classify_entries([{"path": "/tmp/x", "type": "file", "setuid": True, "mode": "4755"}])

        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_classify_world_writable_without_sticky(self):
        findings = classify_entries([{"path": "/srv/share", "type": "dir", "world_writable": True, "sticky": False}])

        self.assertEqual(findings[0]["severity"], "WARN")


class AuditpolTests(unittest.TestCase):
    def test_parse_audit_rules(self):
        parsed = parse_audit_rules("-w /etc/passwd -p wa -k identity\n-a always,exit -S execve\n-e 2\n")

        self.assertTrue(parsed["immutable"])
        self.assertEqual(len(parsed["watches"]), 1)
        self.assertEqual(len(parsed["syscalls"]), 1)

    def test_parse_auditd_conf(self):
        parsed = parse_auditd_conf("max_log_file_action = rotate\n")

        self.assertEqual(parsed["max_log_file_action"], "rotate")

    def test_classify_audit_disabled(self):
        findings = classify_audit_findings("enabled 0", {"watches": [], "syscalls": [], "immutable": False}, {})

        self.assertEqual(findings[0]["severity"], "WARN")


class AccttrailTests(unittest.TestCase):
    def test_parse_last(self):
        rows = parse_last("alice pts/0 10.0.0.1 Mon Jun 1 10:00 still logged in\n")

        self.assertEqual(rows[0]["user"], "alice")
        self.assertEqual(rows[0]["source"], "10.0.0.1")

    def test_parse_lastlog(self):
        rows = parse_lastlog("Username Port From Latest\nalice pts/0 10.0.0.1 Mon Jun 1\n")

        self.assertEqual(rows[0]["user"], "alice")

    def test_parse_passwd_and_uid0_finding(self):
        users = parse_passwd("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0:x:/root:/bin/bash\n")
        findings = classify_account_findings([], users)

        self.assertEqual(findings[0]["severity"], "CRITICAL")


class MountauditTests(unittest.TestCase):
    def test_parse_mountinfo(self):
        rows = parse_mountinfo("1 2 0:1 / /tmp rw,nosuid - tmpfs tmpfs rw\n")

        self.assertEqual(rows[0]["mount"], "/tmp")
        self.assertEqual(rows[0]["fstype"], "tmpfs")

    def test_parse_fstab(self):
        rows = parse_fstab("server:/x /mnt nfs user,rw 0 0\n")

        self.assertEqual(rows[0]["mount"], "/mnt")

    def test_classify_tmp_without_nosuid(self):
        findings = classify_mount_findings([{"mount": "/tmp", "options": ["rw"], "fstype": "tmpfs"}], [])

        self.assertEqual(findings[0]["severity"], "WARN")


class EnvleakTests(unittest.TestCase):
    def test_scan_text_returns_key_not_value(self):
        hits = scan_text("API_TOKEN=supersecret\n")

        self.assertEqual(hits[0]["key"], "API_TOKEN")


class CertwatchTests(unittest.TestCase):
    def test_parse_cert_date(self):
        parsed = parse_cert_date("Jun  1 12:00:00 2026 GMT")

        self.assertIsNotNone(parsed)

    def test_classify_expired_cert(self):
        findings = classify_cert_findings([{"path": "/tmp/cert.pem", "days_remaining": -1}])

        self.assertEqual(findings[0]["severity"], "CRITICAL")


class WebauditTests(unittest.TestCase):
    def test_parse_web_config(self):
        directives = parse_web_config("listen 80;\nautoindex on;\n", "/etc/nginx/site.conf")

        self.assertEqual(directives[0]["key"], "listen")

    def test_classify_autoindex(self):
        findings = classify_web_findings([{"path": "x", "line": "2", "key": "autoindex", "value": "on"}])

        self.assertEqual(findings[0]["severity"], "WARN")


class CloudauditTests(unittest.TestCase):
    def test_scan_cloud_text_redacts_password(self):
        hits = scan_cloud_text("password: hello\nruncmd:\n - curl 169.254.169.254\n", "user-data")

        self.assertTrue(any(hit["kind"] == "cloud-init-sensitive" for hit in hits))
        self.assertTrue(any(hit["kind"] == "metadata-ip" for hit in hits))

    def test_parse_routes(self):
        rows = parse_routes("Iface Destination Gateway Flags\neth0 00000000 01010101 0003\n")

        self.assertEqual(rows[0]["destination"], "eth0")

    def test_classify_metadata_hit(self):
        findings = classify_cloud_findings([{"kind": "metadata-ip", "path": "x", "line": "1"}], [])

        self.assertEqual(findings[0]["severity"], "INFO")


class OpsrunTests(unittest.TestCase):
    def test_select_tools_skips_stateful_by_default(self):
        selected = select_tools("dfir")

        self.assertIn("procaudit", selected)
        self.assertNotIn("evidencetrail", selected)

    def test_select_tools_explicit_list(self):
        selected = select_tools("all", "netaudit,logtriage")

        self.assertEqual(selected, ["netaudit", "logtriage"])

    def test_summarize_reports_keeps_tool_name(self):
        summary = summarize_reports(
            [
                {"tool": "a", "overall": "WARN", "findings": [{"severity": "WARN", "message": "x"}], "warnings": []},
                {"tool": "b", "overall": "OK", "findings": [], "warnings": ["missing"]},
            ]
        )

        self.assertEqual(summary["overall"], "WARN")
        self.assertEqual(summary["findings"][0]["tool"], "a")


if __name__ == "__main__":
    unittest.main()
