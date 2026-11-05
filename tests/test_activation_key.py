"""adaudit_push.parse_activation_key: the environments, the key's checks, and
that no error message carries the key."""
import unittest

import adaudit_push as ap
from tests._keys import AGENT, activation, b64, license_key


class ValidKeys(unittest.TestCase):
    def test_standard_key(self):
        lic = ap.parse_activation_key(activation(e="prod"))
        self.assertEqual(lic.company_id, 12)
        self.assertEqual(str(lic.agent_id), AGENT)
        self.assertEqual(lic.environment, "prod")
        self.assertEqual(lic.license_key, license_key())

    def test_environments(self):
        for env, url in (("prod", "https://api.fortifydata.com"),
                         ("eu", "https://api.eu.fortifydata.com"),
                         ("test", "https://api.test.fortifydata.com"),
                         ("TEST", "https://api.test.fortifydata.com")):
            with self.subTest(env=env):
                self.assertEqual(ap.parse_activation_key(activation(e=env)).api_url(), url)

    def test_explicit_url_wins(self):
        lic = ap.parse_activation_key(activation(e="prod"))
        self.assertEqual(lic.api_url("http://127.0.0.1:9"), "http://127.0.0.1:9")

    def test_urlsafe_unpadded(self):
        key = activation(k=license_key(urlsafe=True, pad=False), e="test", urlsafe=True,
                         pad=False)
        self.assertEqual(ap.parse_activation_key(key).company_id, 12)

    def test_bare_license_key_needs_url(self):
        lic = ap.parse_activation_key(license_key())
        self.assertEqual(lic.company_id, 12)
        self.assertIsNone(lic.environment)
        with self.assertRaisesRegex(ap.LicenseKeyError, "explicitly"):
            lic.api_url()

    def test_whitespace_and_extra_fields(self):
        self.assertEqual(ap.parse_activation_key("  " + activation(e="prod") + "\n").company_id, 12)
        self.assertEqual(ap.parse_activation_key(activation(e="prod", extra={"x": 1})).company_id,
                         12)

    def test_repr_hides_key(self):
        self.assertNotIn(license_key(), repr(ap.parse_activation_key(activation(e="prod"))))

    def test_other_environment_needs_url(self):
        for env in ("us", "mars", "dev", "training"):
            with self.subTest(env=env):
                lic = ap.parse_activation_key(activation(e=env))
                with self.assertRaisesRegex(ap.LicenseKeyError, "only prod, eu, test"):
                    lic.api_url()
                self.assertEqual(lic.api_url("https://x.example"), "https://x.example")


class InvalidKeys(unittest.TestCase):
    CASES = [
        ("no e", activation(), "no environment"),
        ("e empty", activation(e=""), "no environment"),
        ("e not a name", activation(e="a b/c"), "not a name"),
        ("e not text", activation(extra={"e": 5}), "not text"),
        ("wrong integration", activation(k=license_key(integ="OTHER"), e="prod"), "integration"),
        ("wrong collector type", activation(k=license_key(ctype="NESSUS"), e="prod"),
         "collector type"),
        ("agent not a UUID", activation(k=license_key(agent="not-a-uuid"), e="prod"), "UUID"),
        ("company 7 digits", activation(k=license_key(company="0000012"), e="prod"), "8 digits"),
        ("company zero", activation(k=license_key(company="00000000"), e="prod"), "0"),
        ("3 parts", activation(k="00000012.QQ==.QQ==", e="prod"), "3 dot-separated"),
        ("not base64", "!!!not-base64###", "not base64"),
        ("JSON array", b64("[1,2]"), "JSON object"),
        ("not JSON", b64("hello"), "JSON"),
        ("missing k", b64('{"e":"us"}'), "empty"),
        ("too long", "A" * 9000, "too long"),
        ("empty", "   ", "empty"),
        ("mixed alphabets", "ab+c-d==", "not base64"),
    ]

    def test_refused_without_leaking(self):
        for name, text, needle in self.CASES:
            with self.subTest(name):
                with self.assertRaises(ap.LicenseKeyError) as ctx:
                    ap.parse_activation_key(text)
                message = str(ctx.exception)
                self.assertIn(needle, message)
                for secret in (license_key(), text):
                    if len(secret) > 12:
                        self.assertNotIn(secret, message)


if __name__ == "__main__":
    unittest.main()
