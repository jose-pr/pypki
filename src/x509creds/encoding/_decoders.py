from typing import TYPE_CHECKING, BinaryIO as _BinIO
from typing_extensions import TypeAlias
from os import PathLike
from pathlib import Path
from io import BytesIO
from abc import (
    ABC as _ABC,
    abstractmethod as _method,
)

if TYPE_CHECKING:
    from . import Encoding, PasswordLike

ValidPath: TypeAlias = "str|PathLike"
ProtectedByteEncoded: TypeAlias = "tuple[bytes, Encoding, PasswordLike]"
EncodedBytes: TypeAlias = "tuple[bytes, Encoding] | ProtectedByteEncoded"
ProtectedEncodedFile: TypeAlias = (
    "tuple[ValidPath, Encoding, PasswordLike]|tuple[ValidPath, PasswordLike]"
)
EncodedFile: TypeAlias = "tuple[ValidPath, Encoding] | ValidPath | ProtectedEncodedFile"
Encoded: TypeAlias = "EncodedFile| EncodedBytes"

_ENCODING_SUFFIX_MAP: "dict[str,Encoding]" = {}


def encoding_from_suffix(ext: str):
    if not ext.startswith("."):
        ext = "." + ext
    return _ENCODING_SUFFIX_MAP[ext]


class EncodedIO(_ABC):
    encoding: "Encoding"
    password: "PasswordLike"

    def __new__(cls, encoded: Encoded):
        if not isinstance(encoded, tuple) or not isinstance(encoded[0], bytes):
            return EncodedFileIO(encoded)
        else:
            return EncodedBytesIO(encoded)

    def read_bytes(self) -> bytes:
        with self.open() as bin:
            return bin.read()

    def open(self) -> "_BinIO":
        pass

    def close(self):
        pass

    def __enter__(self):
        return self.open()

    def __exit__(self, *args):
        self.close()


class EncodedBytesIO(EncodedIO):
    data: bytes

    def __new__(cls, encoded: EncodedBytes):
        inst = object.__new__(cls)
        if len(encoded) == 2:
            inst.data, inst.encoding = encoded
            inst.password = None
        else:
            inst.data, inst.encoding, inst.password = encoded
        return inst

    def read_bytes(self):
        return self.data

    def open(self):
        return BytesIO(self.data)


class EncodedFileIO(EncodedIO):
    path: Path

    def __new__(cls, encoded: EncodedFile):
        inst = object.__new__(cls)

        if not isinstance(encoded, tuple):
            path = encoded
            encoding = None
            inst.password = None
        elif len(encoded) == 2:
            path, encoding_or_password = encoded
            if isinstance(encoding_or_password, int):
                encoding = encoding_or_password
                inst.password = None
            else:
                inst.password = encoding_or_password
                encoding = None
        else:
            path, encoding, inst.password = encoded

        inst.path = Path(path)
        if not encoding:
            encoding = encoding_from_suffix(inst.path.suffix)
        elif isinstance(encoding, str):
            encoding = encoding_from_suffix["." + encoding]
        inst.encoding = encoding
        return inst

    def open(self, mode: str = "rb"):
        self._io = self.path.open(mode)
        return self._io

    def close(self):
        return self._io.close()
