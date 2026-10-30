"""Create a demo CA and a server certificate with explicit DNS/IP SANs."""

import argparse
import datetime
import ipaddress
from collections.abc import Sequence
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _build_ca_certificate(
    ca_key: rsa.RSAPrivateKey, now: datetime.datetime
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Collab demo CA")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )


def _build_server_certificate(
    ca_certificate: x509.Certificate,
    ca_private_key: rsa.RSAPrivateKey,
    server_private_key: rsa.RSAPrivateKey,
    names: Sequence[str],
    now: datetime.datetime,
) -> x509.Certificate:
    sans = []
    for name in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(ca_certificate.subject)
        .public_key(server_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )


def _write_private_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
    """Create a private PEM file exclusively and restrict its filesystem mode."""
    with path.open("xb") as stream:
        path.chmod(0o600)
        stream.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


def generate(directory: str | Path, names: Sequence[str]) -> None:
    """Create a local demo CA and a server certificate without overwriting outputs.

    Names become DNS/IP SANs in their original order. Private keys remain in the
    output directory; clients need only ca.crt. Private-key files are created with
    mode 0600 where supported. Filesystem failures may leave partial output.

    Args:
        directory: Output directory, created with parents if necessary.
        names: Nonempty sequence of DNS names/IPs; the first is also the common name.

    Raises:
        ValueError: Any expected output already exists or a certificate name is invalid.
        OSError: Directory creation or output writing fails.
    """
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    ca_key_path = root / "ca.key"
    ca_cert_path = root / "ca.crt"
    server_key_path = root / "server.key"
    server_cert_path = root / "server.crt"
    if any(
        path.exists()
        for path in (ca_key_path, ca_cert_path, server_key_path, server_cert_path)
    ):
        raise ValueError("Certificate files already exist; choose a new directory")

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_certificate = _build_ca_certificate(ca_private_key, now)
    server_certificate = _build_server_certificate(
        ca_certificate, ca_private_key, server_private_key, names, now
    )
    _write_private_key(ca_key_path, ca_private_key)
    _write_private_key(server_key_path, server_private_key)
    ca_cert_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    server_cert_path.write_bytes(
        server_certificate.public_bytes(serialization.Encoding.PEM)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="certs")
    parser.add_argument("--names", nargs="+", default=["localhost", "127.0.0.1"])
    args = parser.parse_args()
    generate(args.out, args.names)
    print("Created CA and server certificate. Share only ca.crt with clients.")


if __name__ == "__main__":
    main()
