"""Create a demo CA and a server certificate with explicit DNS/IP SANs."""

import argparse
import datetime
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate(directory, names):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    paths = [root / n for n in ("ca.key", "ca.crt", "server.key", "server.crt")]
    if any(p.exists() for p in paths):
        raise ValueError("Certificate files already exist; choose a new directory")
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Collab demo CA")])
    ca = (
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
    sans = []
    for name in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    for path, private in ((paths[0], ca_key), (paths[2], key)):
        with path.open("xb") as stream:
            path.chmod(0o600)
            stream.write(
                private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
    paths[1].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths[3].write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="certs")
    parser.add_argument("--names", nargs="+", default=["localhost", "127.0.0.1"])
    opts = parser.parse_args()
    generate(opts.out, opts.names)
    print("Created CA and server certificate. Share only ca.crt with clients.")


if __name__ == "__main__":
    main()
