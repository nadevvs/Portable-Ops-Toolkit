import tempfile
import unittest
from pathlib import Path

from common.detect import parse_key_value_file
from common.output import format_table
from common.redact import redact_text
from common.state import DEFAULT_STATE_DIR, TOOLKIT_ROOT, ensure_state_dir, resolve_state_dir
from common.systemd import parse_failed_units


class DetectTests(unittest.TestCase):
    def test_parse_key_value_file(self):
        parsed = parse_key_value_file(
            '''
            NAME="Example Linux"
            ID=example
            # ignored
            BROKEN
            '''
        )

        self.assertEqual(parsed["NAME"], "Example Linux")
        self.assertEqual(parsed["ID"], "example")
        self.assertNotIn("BROKEN", parsed)


class OutputTests(unittest.TestCase):
    def test_format_table_includes_headers_and_rows(self):
        table = format_table([{"name": "ssh", "state": "active"}], ["name", "state"])

        self.assertIn("name", table)
        self.assertIn("state", table)
        self.assertIn("ssh", table)
        self.assertIn("active", table)


class StateTests(unittest.TestCase):
    def test_resolve_state_dir_defaults_to_ops_state(self):
        self.assertEqual(resolve_state_dir(None), TOOLKIT_ROOT / DEFAULT_STATE_DIR)

    def test_ensure_state_dir_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "state"
            result = ensure_state_dir(target)

            self.assertTrue(result.is_dir())


class RedactTests(unittest.TestCase):
    def test_redact_secret_like_values(self):
        text = redact_text("run --token abc SECRET_KEY=def https://user:pass@example.test")

        self.assertNotIn("abc", text)
        self.assertNotIn("def", text)
        self.assertNotIn("user:pass@", text)


class SystemdTests(unittest.TestCase):
    def test_parse_failed_units_handles_bullet_prefix(self):
        units = parse_failed_units(
            """
  UNIT             LOAD   ACTIVE SUB    DESCRIPTION
● nginx.service    loaded failed failed A web server
  other.timer      loaded failed failed A timer
"""
        )

        self.assertEqual(units, ["nginx.service", "other.timer"])


if __name__ == "__main__":
    unittest.main()
