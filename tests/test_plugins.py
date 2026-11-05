"""Every plugin in plugins/ loads and passes adaudit.py's checks."""
import contextlib
import io
import unittest
from pathlib import Path

import adaudit

PLUGINS = Path(__file__).resolve().parent.parent / "plugins"


class Plugins(unittest.TestCase):
    def test_all_load(self):
        with contextlib.redirect_stdout(io.StringIO()):
            plugins, failures, retired = adaudit.discover_plugins(PLUGINS)
        self.assertEqual(failures, [])
        self.assertGreater(len(plugins), 300)
        ids = [p["plugin_id"] for p in plugins] + [r["plugin_id"] for r in retired]
        self.assertEqual(len(ids), len(set(ids)), "duplicate plugin_id")


if __name__ == "__main__":
    unittest.main()
