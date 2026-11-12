import unittest

from garbage_intel.net import (
    NetworkError,
    NetworkPolicyError,
    fetch,
    is_public_address,
    validate_url,
)


class FakeResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self._headers = headers
        self._body = body

    def getheaders(self):
        return list(self._headers.items())

    def read(self, amount=-1):
        if amount is None or amount < 0:
            return self._body
        chunk, self._body = self._body[:amount], self._body[amount:]
        return chunk


class FakeConnection:
    """Replays scripted responses and records where each request was sent."""

    def __init__(self, script, log, scheme, host, address, port, timeout):
        self.script = script
        self.log = log
        self.entry = {"scheme": scheme, "host": host, "address": address, "port": port}

    def request(self, method, target, body=None, headers=None):
        self.entry.update({"method": method, "target": target, "headers": headers})
        self.log.append(self.entry)

    def getresponse(self):
        return self.script.pop(0)

    def close(self):
        pass


def factory(script, log):
    def build(scheme, host, address, port, timeout):
        return FakeConnection(script, log, scheme, host, address, port, timeout)

    return build


def resolver(mapping):
    def resolve(host, port):
        return mapping[host]

    return resolve


class AddressPolicyTests(unittest.TestCase):
    def test_public_and_non_public_addresses(self):
        self.assertTrue(is_public_address("8.8.8.8"))
        self.assertTrue(is_public_address("2606:4700:4700::1111"))
        for value in (
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "not-an-ip",
        ):
            self.assertFalse(is_public_address(value), value)

    def test_url_validation_refuses_unsafe_shapes(self):
        refused = [
            "ftp://example.com/",
            "http://example.com/",
            "https://user:pass@example.com/",
            "https://example.com:8443/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://localhost/",
            "https://printer.local/",
            "https://example.com/\nX: y",
            "https:///nohost",
        ]
        for url in refused:
            with self.assertRaises(NetworkPolicyError, msg=url):
                validate_url(url)
        self.assertEqual(
            validate_url("https://Example.com./a?b=1"),
            ("https", "example.com", 443, "/a?b=1"),
        )
        self.assertEqual(validate_url("http://example.com/", allow_http=True)[0], "http")

    def test_allowed_hosts_are_enforced(self):
        with self.assertRaises(NetworkPolicyError):
            validate_url("https://other.example/", allowed_hosts=["api.example"])
        validate_url("https://api.example/", allowed_hosts=["API.example"])


class FetchTests(unittest.TestCase):
    def test_fetch_pins_resolved_address_and_hashes_body(self):
        log = []
        script = [FakeResponse(200, {"Content-Type": "application/json"}, b'{"ok":true}')]
        result = fetch(
            "https://api.example/v1?q=1",
            resolver=resolver({"api.example": ["93.184.216.34"]}),
            connection_factory=factory(script, log),
        )
        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, b'{"ok":true}')
        self.assertEqual(result.address, "93.184.216.34")
        self.assertEqual(len(result.sha256), 64)
        self.assertEqual(log[0]["address"], "93.184.216.34")
        self.assertEqual(log[0]["host"], "api.example")
        self.assertEqual(log[0]["target"], "/v1?q=1")
        self.assertEqual(log[0]["headers"]["Accept-Encoding"], "identity")

    def test_dns_answer_with_private_address_is_refused(self):
        log = []
        with self.assertRaises(NetworkPolicyError):
            fetch(
                "https://rebind.example/",
                resolver=resolver({"rebind.example": ["93.184.216.34", "10.0.0.5"]}),
                connection_factory=factory([], log),
            )
        self.assertEqual(log, [])

    def test_redirect_to_private_target_is_refused(self):
        log = []
        script = [FakeResponse(302, {"Location": "https://inner.example/"}, b"")]
        with self.assertRaises(NetworkPolicyError):
            fetch(
                "https://api.example/",
                resolver=resolver(
                    {"api.example": ["93.184.216.34"], "inner.example": ["127.0.0.1"]}
                ),
                connection_factory=factory(script, log),
            )
        self.assertEqual(len(log), 1)

    def test_redirects_are_followed_and_revalidated(self):
        log = []
        script = [
            FakeResponse(301, {"Location": "/moved"}, b""),
            FakeResponse(200, {}, b"done"),
        ]
        result = fetch(
            "https://api.example/start",
            resolver=resolver({"api.example": ["93.184.216.34"]}),
            connection_factory=factory(script, log),
        )
        self.assertEqual(result.final_url, "https://api.example/moved")
        self.assertEqual(result.redirects, ["https://api.example/moved"])
        self.assertEqual([entry["target"] for entry in log], ["/start", "/moved"])

    def test_https_to_http_downgrade_is_refused(self):
        script = [FakeResponse(302, {"Location": "http://api.example/"}, b"")]
        with self.assertRaises(NetworkPolicyError):
            fetch(
                "https://api.example/",
                allow_http=True,
                resolver=resolver({"api.example": ["93.184.216.34"]}),
                connection_factory=factory(script, []),
            )

    def test_redirect_limit(self):
        script = [FakeResponse(302, {"Location": "/loop"}, b"") for _ in range(5)]
        with self.assertRaises(NetworkError):
            fetch(
                "https://api.example/",
                max_redirects=2,
                resolver=resolver({"api.example": ["93.184.216.34"]}),
                connection_factory=factory(script, []),
            )

    def test_body_limit_by_header_and_by_stream(self):
        declared = [FakeResponse(200, {"Content-Length": "999"}, b"x" * 999)]
        with self.assertRaises(NetworkError):
            fetch(
                "https://api.example/",
                max_bytes=100,
                resolver=resolver({"api.example": ["93.184.216.34"]}),
                connection_factory=factory(declared, []),
            )
        streamed = [FakeResponse(200, {}, b"x" * 101)]
        with self.assertRaises(NetworkError):
            fetch(
                "https://api.example/",
                max_bytes=100,
                resolver=resolver({"api.example": ["93.184.216.34"]}),
                connection_factory=factory(streamed, []),
            )

    def test_header_injection_and_methods_are_refused(self):
        with self.assertRaises(NetworkPolicyError):
            fetch("https://api.example/", headers={"X": "a\r\nB: c"})
        with self.assertRaises(NetworkPolicyError):
            fetch("https://api.example/", method="DELETE")


if __name__ == "__main__":
    unittest.main()
