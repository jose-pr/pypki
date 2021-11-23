from enum import Enum
from openssl_engine import *


class DISPLAY_FORMAT(Enum):
    SUMMARY = 1
    FRIENDLY_NAME = 2
    FULL = 4
    PEM = 8
    XXX = 16
    PRIV_KEY_INFO = 32


class DEBUG_LEVEL(Enum):
    ERROR = 1
    TRACE = 2

class CAPIEngine(SSLEngine):
    def __init__(self, src: str | SSLEngine = "capi") -> None:
        super().__init__(src)

    def set_store(self, name: str):
        self.ctrl_cmd_string("store_name", name)

    def list_certs(
        self, store: str | None = None, format: DISPLAY_FORMAT | None = None
    ) -> list[bytes]:
        if format:
            self.ctrl_cmd_string("list_options", format.value)
        if store:
            self.set_store(store)
        return [
            cert.split(sep=b"\n", maxsplit=1)[1]
            for cert in self.ctrl_cmd_string("list_certs", capture=True)
            .strip(b"\n")
            .split(b"\nCertificate ")
        ]

    def lookup_cert(self, search):
        self.ctrl_cmd_string("lookup_cert", search)

    def debug_level(self, level: DEBUG_LEVEL):
        self.ctrl_cmd_string("debug_level", level.value)

    def debug_file(self, path: str):
        self.ctrl_cmd_string("debug_file", path)

    def list_csps(self):
        self.ctrl_cmd_string("list_csps")

    def list_containers(self):
        self.ctrl_cmd_string("list_containers")
