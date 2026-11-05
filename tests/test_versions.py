"""collector_daemon.image_version / strip_v: the version reported to the
platform comes from the image's COLLECTOR_VERSION, without a "v"."""
import os
import re
import unittest
from pathlib import Path
from unittest import mock

import collector_daemon as cd

ROOT = Path(__file__).resolve().parent.parent


class ImageVersion(unittest.TestCase):
    def check(self, value, expected):
        env = {k: v for k, v in os.environ.items() if k != "COLLECTOR_VERSION"}
        if value is not None:
            env["COLLECTOR_VERSION"] = value
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(cd.image_version(), expected)

    def test_from_build(self):
        self.check("1.2.0", "1.2.0")
        self.check("v1.2.0", "1.2.0")
        self.check(" 1.3.0-dev.17 ", "1.3.0-dev.17")
        self.check("1.3.0+build.5", "1.3.0+build.5")

    def test_fallback_to_daemon_version(self):
        self.check(None, cd.VERSION)
        self.check("", cd.VERSION)
        self.check("latest", cd.VERSION)
        self.check("1.2", cd.VERSION)

    def test_strip_v(self):
        self.assertEqual(cd.strip_v("v1.2.0"), "1.2.0")
        self.assertEqual(cd.strip_v("V1.2.0"), "1.2.0")
        self.assertEqual(cd.strip_v("1.2.0"), "1.2.0")

    def test_daemon_version_is_semver(self):
        self.assertRegex(cd.VERSION, r"^\d+\.\d+\.\d+$")


@unittest.skipUnless((ROOT / "docker").is_dir(), "no docker/ directory (running inside the image)")
class Packaging(unittest.TestCase):
    def test_compose_and_install_use_the_same_image(self):
        compose = (ROOT / "docker" / "compose.yaml").read_text()
        install = (ROOT / "docker" / "install.sh").read_text()
        image = re.search(r"COLLECTOR_IMAGE:-([^}]+)\}", compose).group(1)
        self.assertEqual(re.search(r'^IMAGE_DEFAULT="([^"]+)"', install, re.M).group(1), image)
        # The default is the release being prepared: the daemon's own version.
        self.assertEqual(image, f"fortifydata/collector-ad:v{cd.VERSION}")


if __name__ == "__main__":
    unittest.main()
