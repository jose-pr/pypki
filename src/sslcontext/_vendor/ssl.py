from enum import IntEnum as _IntEnum, Enum as _Enum
import os as _os
from typing import Sequence as _Sequence, Iterator as _Iterator
import warnings as _warnings

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
    from ssl import VerifyMode, SSLError, Purpose, SSLContext as _SSLContext

    if _os.name == "nt":
        from ssl import enum_certificates

        WINDOWS_TRUSTED_STORES: "_Sequence[str]" = _SSLContext._windows_cert_stores

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

    if _os.name == "nt":
        WINDOWS_TRUSTED_STORES = ("CA", "ROOT")

        try:
            import wincertstore as _store

            def enum_certificates(
                storename: str,
            ) -> "_Iterator[tuple[bytes, str, bool|str]]":
                store = _store.CertSystemStore(storename)
                try:
                    cert: _store.CERT_CONTEXT
                    for cert in store.itercerts():
                        yield cert.get_encoded(), "x509_asn" if cert.encoding_type == "CERTIFICATE" else cert.encoding_type, cert.enhanced_keyusage()
                finally:
                    store.close()

        except ImportError:
            _warnings.warn(
                "Unable to enumerate Windows certificate store, install wincertstore"
            )

            def enum_certificates(
                storename: str,
            ) -> "_Iterator[tuple[bytes, str, bool|str]]":
                _warnings.warn(
                    f"Unable to enumerate Windows certificate store: {storename}, install wincertstore"
                )

                return []
