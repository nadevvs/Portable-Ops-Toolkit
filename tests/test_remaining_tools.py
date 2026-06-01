import tempfile
import unittest
from pathlib import Path

from blackbox import parse_df, parse_loadavg, parse_meminfo, parse_ss_summary, summarize
from croninv import check_suspicious, parse_crontab, parse_systemd_timers
from permdrift import ExpectedPath, compare_expected_actual, parse_config
from serverdoctor import classify_findings, overall_status
from sshexpose import classify_findings as classify_ssh_findings
from sshexpose import inspect_authorized_keys, parse_auth_log, parse_sshd_T, parse_sshd_config


class CroninvTests(unittest.TestCase):
    def test_parse_crontab_regular_and_special(self):
        jobs = parse_crontab(
            """
SHELL=/bin/sh
17 * * * * root run-parts /etc/cron.hourly
@reboot deploy /opt/app/start.sh
""",
            "/etc/crontab",
            True,
        )

        self.assertEqual(len(jobs), 2)
        self.assertEqual(jobs[0]["user"], "root")
        self.assertEqual(jobs[1]["schedule"], "@reboot")

    def test_check_suspicious_flags_download_pipe(self):
        reasons = check_suspicious({"user": "root", "command": "curl http://x | sh"})

        self.assertIn("pipes downloaded content to shell", reasons)

    def test_parse_systemd_timers_finds_unit(self):
        timers = parse_systemd_timers(
            """
NEXT LEFT LAST PASSED UNIT ACTIVATES
Mon 2026-06-01 10:00 UTC 1h ago Mon 2026-06-01 09:00 UTC 2h ago apt.timer apt.service
"""
        )

        self.assertEqual(timers[0]["unit"], "apt.timer")
        self.assertEqual(timers[0]["activates"], "apt.service")


class PermdriftTests(unittest.TestCase):
    def test_parse_config_supports_optional(self):
        entries = parse_config("/tmp/a | 600 | root | root | file | note | optional")

        self.assertTrue(entries[0].optional)
        self.assertEqual(entries[0].path, "/tmp/a")

    def test_missing_optional_is_warning(self):
        entry = ExpectedPath("/tmp/missing", "600", "root", "root", "file", optional=True)
        result = compare_expected_actual(entry, {"path": "/tmp/missing", "exists": False})

        self.assertEqual(result["severity"], "WARN")

    def test_world_writable_is_critical(self):
        entry = ExpectedPath("/tmp/a", "644", "root", "root", "file")
        result = compare_expected_actual(
            entry,
            {
                "path": "/tmp/a",
                "exists": True,
                "type": "file",
                "mode": "666",
                "owner": "root",
                "group": "root",
                "world_writable": True,
                "setuid": False,
            },
        )

        self.assertEqual(result["severity"], "CRITICAL")


class SshexposeTests(unittest.TestCase):
    def test_parse_sshd_config(self):
        parsed = parse_sshd_config(
            """
Port 2222
PermitRootLogin no
PasswordAuthentication yes
Match User deploy
  PasswordAuthentication no
"""
        )

        self.assertEqual(parsed["Port"], "2222")
        self.assertEqual(parsed["PasswordAuthentication"], "yes")
        self.assertTrue(parsed["_match_blocks_present"])

    def test_parse_sshd_T(self):
        parsed = parse_sshd_T("permitrootlogin no\npasswordauthentication no\n")

        self.assertEqual(parsed["permitrootlogin"], "no")

    def test_ssh_findings_detect_root_login(self):
        findings = classify_ssh_findings({"permitrootlogin": "yes"}, [], [])

        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_parse_auth_log_counts_failed_and_accepted(self):
        summary = parse_auth_log(
            [
                "sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
                "sshd[1]: Accepted publickey for deploy from 5.6.7.8 port 22 ssh2",
            ]
        )

        self.assertEqual(summary["failed_logins"], 1)
        self.assertEqual(summary["accepted_logins"], 1)

    def test_inspect_authorized_keys_flags_writable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "authorized_keys"
            path.write_text("ssh-ed25519 AAAATEST comment\n", encoding="utf-8")
            path.chmod(0o666)

            data = inspect_authorized_keys(path, "deploy")

            self.assertEqual(data["keys"], 1)
            self.assertTrue(data["writable_by_group_or_other"])


class BlackboxTests(unittest.TestCase):
    def test_parse_loadavg(self):
        parsed = parse_loadavg("0.21 0.18 0.12 1/120 999")

        self.assertEqual(parsed["load1"], 0.21)
        self.assertEqual(parsed["running_processes"], 1)

    def test_parse_meminfo(self):
        parsed = parse_meminfo("MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 100 kB\nSwapFree: 40 kB\n")

        self.assertEqual(parsed["MemUsedPercent"], 75.0)
        self.assertEqual(parsed["SwapUsedPercent"], 60.0)

    def test_parse_df(self):
        disks = parse_df("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/a 100 90 10 90% /\n")

        self.assertEqual(disks[0]["mount"], "/")
        self.assertEqual(disks[0]["used_percent"], 90)

    def test_parse_ss_summary(self):
        summary = parse_ss_summary("tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:123\nudp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\n")

        self.assertEqual(summary["tcp_established"], 1)
        self.assertEqual(summary["udp"], 1)

    def test_summarize_detects_reboot(self):
        summary = summarize(
            [
                {"timestamp": "2026-06-01T00:00:00+00:00", "boot_id": "a", "load": {"load1": 1}, "memory": {"MemUsedPercent": 20}},
                {"timestamp": "2026-06-01T01:00:00+00:00", "boot_id": "b", "load": {"load1": 2}, "memory": {"MemUsedPercent": 30}},
            ]
        )

        self.assertEqual(summary["reboots"], 1)
        self.assertEqual(summary["max_load1"]["value"], 2)


class ServerdoctorTests(unittest.TestCase):
    def test_classify_public_db_listener_is_critical(self):
        findings = classify_findings(
            {
                "memory": {"MemUsedPercent": 10, "SwapUsedPercent": 0},
                "disk": [],
                "services": {"failed_units": []},
                "listeners": [{"exposure": "all-interfaces", "port": "5432"}],
                "logs": {},
            }
        )

        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(overall_status(findings), "CRITICAL")


if __name__ == "__main__":
    unittest.main()
