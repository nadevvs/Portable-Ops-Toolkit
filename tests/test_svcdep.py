import unittest

from common.cmd import CommandResult
from svcdep import (
    command_warning,
    extract_notable_logs,
    normalize_service_name,
    parse_ps_output,
    parse_ss_output,
    parse_systemctl_show,
)


class SvcdepParserTests(unittest.TestCase):
    def test_normalize_service_name_adds_service_suffix(self):
        self.assertEqual(normalize_service_name("nginx"), "nginx.service")
        self.assertEqual(normalize_service_name("ssh.service"), "ssh.service")
        self.assertEqual(normalize_service_name("worker@blue.service"), "worker@blue.service")

    def test_parse_systemctl_show_extracts_fields(self):
        parsed = parse_systemctl_show(
            """
Id=nginx.service
Description=A high performance web server
ActiveState=active
SubState=running
MainPID=923
FragmentPath=/lib/systemd/system/nginx.service
IgnoredField=value
"""
        )

        self.assertEqual(parsed["ActiveState"], "active")
        self.assertEqual(parsed["MainPID"], "923")
        self.assertEqual(parsed["FragmentPath"], "/lib/systemd/system/nginx.service")
        self.assertNotIn("IgnoredField", parsed)

    def test_parse_ss_output_extracts_listener_process(self):
        parsed = parse_ss_output(
            """
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      511    0.0.0.0:80     0.0.0.0:*     users:(("nginx",pid=923,fd=6))
udp   UNCONN 0      0      127.0.0.1:323   0.0.0.0:*     users:(("chronyd",pid=101,fd=5))
"""
        )

        self.assertEqual(parsed[0]["proto"], "tcp")
        self.assertEqual(parsed[0]["state"], "LISTEN")
        self.assertEqual(parsed[0]["address"], "0.0.0.0")
        self.assertEqual(parsed[0]["port"], "80")
        self.assertEqual(parsed[0]["process"], "nginx")
        self.assertEqual(parsed[0]["pid"], 923)
        self.assertEqual(parsed[1]["proto"], "udp")
        self.assertEqual(parsed[1]["address"], "127.0.0.1")
        self.assertEqual(parsed[1]["port"], "323")

    def test_parse_ps_output_extracts_processes(self):
        parsed = parse_ps_output(
            """
    PID    PPID USER     COMMAND         COMMAND
    923       1 root     nginx           nginx: master process
    924     923 www-data nginx           nginx: worker process
"""
        )

        self.assertEqual(parsed[0]["pid"], 923)
        self.assertEqual(parsed[1]["ppid"], 923)
        self.assertEqual(parsed[1]["user"], "www-data")

    def test_extract_notable_logs_flags_expected_terms(self):
        notable = extract_notable_logs(
            [
                "Jun 01 nginx started cleanly",
                "Jun 01 nginx[923]: connect() failed permission denied",
                "Jun 01 nginx[923]: worker timeout",
            ]
        )

        self.assertEqual(len(notable), 2)
        self.assertEqual(notable[0]["match"], "failed")
        self.assertEqual(notable[1]["match"], "timeout")

    def test_command_warning_handles_missing_command(self):
        result = CommandResult(
            args=["systemctl"],
            returncode=127,
            stdout="",
            stderr="",
            missing=True,
        )

        self.assertEqual(command_warning("systemctl show", result), "systemctl show: command not available")


if __name__ == "__main__":
    unittest.main()
