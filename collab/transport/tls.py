"""Verified TLS contexts shared by CLI and Web backend."""

import ssl


def client_context(cafile: str | None) -> ssl.SSLContext:
    """Create a TLS context that verifies the server certificate and identity.

    Args:
        cafile: PEM CA path, or None to load system trust roots.

    Returns:
        A context requiring TLS 1.2 or later and hostname verification.
    """
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """Load the server identity into a TLS 1.2-or-later context.

    Args:
        certfile: PEM server certificate or certificate-chain path.
        keyfile: Matching PEM private-key path.

    Returns:
        A server context with the certificate chain loaded.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile, keyfile)
    return context
