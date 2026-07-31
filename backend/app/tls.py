"""
One place that decides how outbound TLS trusts the corporate proxy CA.

Three callers need identical behaviour: the API server, the live evals, and the
review script. They used to differ, which meant `pytest -m eval` failed with
CERTIFICATE_VERIFY_FAILED on a machine where the server worked fine.
"""

import os

import truststore

# Debian/Ubuntu location, where update-ca-certificates writes during the image build.
LINUX_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"


def resolve_ca_bundle(current: str | None, bundle_path: str = LINUX_CA_BUNDLE) -> str | None:
    """
    Decide what SSL_CERT_FILE should be, without touching the environment.

    An existing value always wins: if someone set it deliberately, respect it.
    """
    if current:
        return current
    return bundle_path if os.path.exists(bundle_path) else None


def configure_trust() -> None:
    """
    Make outbound HTTPS trust the OS certificate store. Safe to call more than once.

    truststore covers the macOS Keychain. It does not pick up the Linux container's
    bundle, so that case is handled by setting SSL_CERT_FILE before injection.
    """
    resolved = resolve_ca_bundle(os.environ.get("SSL_CERT_FILE"))
    if resolved:
        os.environ["SSL_CERT_FILE"] = resolved
    truststore.inject_into_ssl()
