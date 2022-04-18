from enum import IntEnum as _IntEnum, Enum as _Enum

try:
    from ssl import PROTOCOL_TLS

    PROTOCOL_SSLv23 = PROTOCOL_TLS
except ImportError:
    PROTOCOL_SSLv23 = PROTOCOL_TLS = 2

try:
    from ssl import PROTOCOL_TLS_CLIENT
except ImportError:
    PROTOCOL_TLS_CLIENT = PROTOCOL_TLS

try:
    from ssl import PROTOCOL_TLSv1
except ImportError:
    PROTOCOL_TLSv1 = 3

try:
    from ssl import VerifyMode, SSLError, Purpose, _ASN1Object
except ImportError:

    class VerifyMode(_IntEnum):
        CERT_NONE = 0
        CERT_OPTIONAL = 1
        CERT_REQUIRED = 2

    class SSLError(OSError):
        library: str
        reason: str

    class Purpose(str, _Enum):
        """SSLContext purpose flags with X509v3 Extended Key Usage objects"""

        SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
        CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

        @property
        def oid(self):
            return self
