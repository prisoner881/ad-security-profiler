"""platform_client.config_from_health / response_from_health: document 05's
flat configuration in the health check response."""
import copy
import unittest

import platform_client as pc

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

EXAMPLE = {
    "id": 41, "companyId": 14219, "name": "HQ domain controller",
    "agentKey": "9f2c1a44-0b7e-4d19-8f3a-6c5e21b7d004", "type": "AD_AUDIT",
    "status": "HEALTHY", "version": "1.0.3", "targetVersion": "1.0.4", "autoUpgrade": True,
    "imageName": "fortifydata/collector-ad", "lastPingDate": "2026-11-06T09:25:00Z",
    "nextPingDate": "2026-11-06T09:30:00Z", "lastRunDate": "2026-11-06T02:41:17Z",
    "originatingIp": "203.0.113.17",
    "host": "dc01.corp.example.com", "username": "svc_audit@corp.example.com",
    "password": "bind secret", "useLdaps": True, "ldapPort": 636, "caCertificate": PEM,
    "domainFqdn": "corp.example.com", "readSysvol": True, "sysvolKerberos": False,
    "entraTenantId": "6b1d3e90-77aa-4a1f-9c2e-5f4b8d0a1122",
    "entraClientId": "c40f8a12-23de-4b66-9f01-7a3cbb5d9e80",
    "entraClientSecret": "entra secret", "readPtaAgents": False,
    "scheduleTime": "02:30", "scheduleTimeZone": "America/Chicago",
    "configVersion": 7,
}


def example(**changes):
    data = copy.deepcopy(EXAMPLE)
    data.update(changes)
    return data


class Mapping(unittest.TestCase):
    def test_full_example(self):
        cfg = pc.config_from_health(example())
        self.assertEqual(cfg.version, "7")
        self.assertEqual(str(cfg.schedule), "02:30 America/Chicago")
        ad = cfg.ad
        self.assertEqual((ad.dc_host, ad.username, ad.password, ad.ssl, ad.port),
                         ("dc01.corp.example.com", "svc_audit@corp.example.com", "bind secret",
                          True, 636))
        self.assertEqual(ad.ca_cert_pem, PEM)
        self.assertEqual(ad.domain_fqdn, "corp.example.com")
        self.assertTrue(ad.sysvol)
        self.assertFalse(ad.sysvol_kerberos)
        self.assertEqual(cfg.entra.tenant_id, EXAMPLE["entraTenantId"])
        self.assertEqual(cfg.entra.app_id, EXAMPLE["entraClientId"])
        self.assertEqual(cfg.entra.client_secret, "entra secret")
        self.assertFalse(cfg.entra.include_pta_agents)
        self.assertEqual(cfg.warnings, [])

    def test_secrets_not_in_summary_or_repr(self):
        cfg = pc.config_from_health(example())
        for text in (cfg.summary(), repr(cfg)):
            self.assertNotIn("bind secret", text)
            self.assertNotIn("entra secret", text)

    def test_ldap_port_is_explicit(self):
        cfg = pc.config_from_health(example(useLdaps=True, ldapPort=3269))
        self.assertEqual((cfg.ad.ssl, cfg.ad.port), (True, 3269))
        cfg = pc.config_from_health(example(useLdaps=False, ldapPort=389, caCertificate=None))
        self.assertEqual((cfg.ad.ssl, cfg.ad.port), (False, 389))

    def test_no_entra(self):
        cfg = pc.config_from_health(example(entraTenantId=None, entraClientId=None,
                                            entraClientSecret=None))
        self.assertIsNone(cfg.entra)

    def test_entra_incomplete_is_skipped_with_warning(self):
        cfg = pc.config_from_health(example(entraClientSecret=None))
        self.assertIsNone(cfg.entra)
        self.assertTrue(any("Entra" in w for w in cfg.warnings))

    def test_not_configured(self):
        for name in ("host", "username", "password"):
            with self.subTest(name), self.assertRaises(pc.NotConfigured):
                pc.config_from_health(example(**{name: None}))

    def test_unusable(self):
        for changes in ({"host": "dc01 corp"}, {"ldapPort": 70000}, {"useLdaps": "yes"},
                        {"caCertificate": "not a pem"}, {"scheduleTimeZone": "Nowhere/City"}):
            with self.subTest(changes), self.assertRaises(pc.ConfigError):
                pc.config_from_health(example(**changes))


class Response(unittest.TestCase):
    def test_cacheable_has_no_secrets(self):
        resp = pc.response_from_health(example())
        self.assertIsNotNone(resp.config)
        self.assertEqual(resp.config_version, 7)
        for name in pc.SECRET_FIELDS:
            self.assertNotIn(name, resp.cacheable)
        self.assertEqual(resp.cacheable["host"], "dc01.corp.example.com")

    def test_not_configured_response(self):
        resp = pc.response_from_health(example(host=None, username=None, password=None))
        self.assertIsNone(resp.config)
        self.assertTrue(resp.not_configured)

    def test_statuses(self):
        for status, stopped in (("EXPIRED", True), ("DELETED", True), ("HEALTHY", False),
                                ("FAILED", False), ("OUTDATED", False), ("CONFIGURED", False)):
            with self.subTest(status):
                self.assertEqual(pc.response_from_health(example(status=status)).scans_stopped,
                                 stopped)


if __name__ == "__main__":
    unittest.main()
