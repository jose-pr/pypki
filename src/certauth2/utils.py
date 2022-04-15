import ipaddress
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from x509creds import PrivateKey, X509Credentials, Certificate

DEF_KEY_SIZE = 2048
DEF_PUBLIC_EXPONENT = 65537


def into_ip(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def is_ip(ip: str):
    return into_ip(ip) is not None


def cert_builder(
    subject: "x509.Name|str",
    key: "PrivateKey|int|None" = None,
    issuer: "Certificate|None" = None,
    is_ca: "bool|None" = None,
):
    key = key or DEF_KEY_SIZE
    if isinstance(key, int):
        key: PrivateKey = rsa.generate_private_key(DEF_PUBLIC_EXPONENT, key)
    public_key = key.public_key()
    issuer_key = issuer.public_key() if issuer else public_key

    subject = (
        subject
        if isinstance(subject, x509.Name)
        else x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)])
    )

    builder = x509.CertificateBuilder(
        subject_name=subject,
        serial_number=x509.random_serial_number(),
        public_key=public_key,
    )
    if is_ca or (is_ca is None and public_key == issuer_key):
        builder = builder.add_extension(
            x509.BasicConstraints(True, 0), critical=True
        ).add_extension(x509.KeyUsage(key_cert_sign=True, crl_sign=True), critical=True)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key), critical=False
    )
    return builder, key