"""
Live evals make real HTTPS calls, so they need the same trust setup as the server.

Without this the evals fail with CERTIFICATE_VERIFY_FAILED behind a TLS-inspecting
proxy, even though the API server on the same machine works, because only the server
was calling truststore.
"""

from app.tls import configure_trust

configure_trust()
