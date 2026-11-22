import subprocess
import unittest
from unittest.mock import patch

import install


class QuickEdgeTests(unittest.TestCase):
    def check_host(self, logs, invocation="1" * 32, unit=install.QUICK_UNIT):
        def command(*args, **kwargs):
            if args[0] == "systemctl":
                return subprocess.CompletedProcess(args, 0, invocation)
            self.assertIn("_SYSTEMD_INVOCATION_ID=" + invocation, args)
            return subprocess.CompletedProcess(args, 0, logs)

        with patch.object(install, "run", side_effect=command):
            return install.quick_tunnel_host(unit, timeout=0)

    def test_http2_registration_and_current_domain(self):
        logs = ("| https://some-words.trycloudflare.com |\n"
                "INF Registered tunnel connection location=nrt16 protocol=http2")
        self.assertEqual(self.check_host(logs), "some-words.trycloudflare.com")

    def test_rejects_stale_or_incompatible_connection(self):
        for logs, invocation in (
            ("https://valid.trycloudflare.com\nRegistered tunnel connection protocol=quic", "1" * 32),
            ("https://valid.trycloudflare.com", "1" * 32),
            ("https://fake.trycloudflare.com.other.tld\nRegistered tunnel connection protocol=http2", "1" * 32),
            ("https://valid.trycloudflare.com\nRegistered tunnel connection protocol=http2", "0" * 32),
        ):
            with self.subTest(logs=logs, invocation=invocation):
                with self.assertRaises(ValueError):
                    self.check_host(logs, invocation)

    def test_ssh_uses_latest_allocation_and_ignores_banners(self):
        logs = ('{"event":"tcpip-forward","status":"success","address":"old.app.lhr.life"}\n'
                '{"type":"run.localhost.tunnel.registered","data":{"address":"new.app.lhr.life"}}\n'
                'https://admin.localhost.run/')
        self.assertEqual(self.check_host(logs, unit=install.QUICK_SSH_UNIT), "new.app.lhr.life")
        with self.assertRaisesRegex(ValueError, "Host key verification failed"):
            self.check_host("Host key verification failed.", unit=install.QUICK_SSH_UNIT)
