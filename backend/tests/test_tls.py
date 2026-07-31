"""
Trust setup has to work in two places that disagree.

On the Mac the proxy CA is in the Keychain and truststore reads it. In the Linux
container truststore does not find the baked-in bundle, so OpenSSL is pointed at it
directly. Getting this wrong fails every outbound call with CERTIFICATE_VERIFY_FAILED.
"""

from app.tls import resolve_ca_bundle


def test_returns_the_bundle_path_when_it_exists_and_nothing_is_set():
    resolved = resolve_ca_bundle(current=None, bundle_path=__file__)
    assert resolved == __file__


def test_keeps_an_already_configured_bundle():
    resolved = resolve_ca_bundle(current="/somewhere/existing.pem", bundle_path=__file__)
    assert resolved == "/somewhere/existing.pem"


def test_returns_none_when_the_bundle_is_absent():
    resolved = resolve_ca_bundle(current=None, bundle_path="/no/such/bundle.crt")
    assert resolved is None
