
from enum import IntEnum as _IntEnum


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
    from ssl import VerifyMode, SSLError
except ImportError:

    class VerifyMode(_IntEnum):
        CERT_NONE = 0
        CERT_OPTIONAL = 1
        CERT_REQUIRED = 2

    class SSLError(OSError):
        library: str
        reason: str