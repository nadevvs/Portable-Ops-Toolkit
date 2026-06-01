import tempfile
import unittest
from pathlib import Path

from common.detect import parse_key_value_file
from common.output import format_table
from common.state import ensure_state_dir, resolve_state_dir


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
        self.assertEqual(resolve_state_dir(None), Path("ops_state"))

    def test_ensure_state_dir_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "state"
            result = ensure_state_dir(target)

            self.assertTrue(result.is_dir())


if __name__ == "__main__":
    unittest.main()
