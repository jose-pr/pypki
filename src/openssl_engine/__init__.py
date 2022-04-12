import os
from OpenSSL.SSL import Context as SSLContext, _ffi, _lib
from .utils import FdOutputGrabber

_NULL = _ffi.NULL


class SSLEngine:
    def __init__(self, id: "str | _ffi.CData | SSLEngine") -> None:
        if isinstance(id, str):
            try:
                eng = SSLEngine.load_by_id(id)
            except Exception:
                try:
                    eng = SSLEngine.load_dynamic(id)
                except Exception:
                    eng = SSLEngine.load_dynamic(id, path=id)
            ptr = eng.ptr
        elif isinstance(id, SSLEngine):
            ptr = id.ptr
        else:
            ptr = id

        self.ptr = ptr

    def init(self):
        if not _lib.ENGINE_init(self.ptr):
            self.__exit__()
            raise Exception("Could not initialize engine")

    def free(self):
        _lib.ENGINE_free(self.ptr)

    def __enter__(self):
        self.init()
        return self

    def __exit__(self, type, value, traceback):
        self.free()

    def ctrl_cmd_string(
        self,
        cmd: str,
        value: "str | None" = None,
        optional: bool = False,
        capture: bool = False,
    ) -> "None | bytes":

        if capture:
            capture: FdOutputGrabber = FdOutputGrabber("stdout")
            capture.start()

        if not _lib.ENGINE_ctrl_cmd_string(
            self.ptr,
            cmd.encode("utf-8"),
            _NULL if value == None else str(value).encode("utf-8"),
            1 if optional else 0,
        ):
            if capture:
                capture.stop()
            raise Exception(
                "Error with engine string control command: %s%s"
                % (cmd, "" if value == None else ":" + value)
            )
        if capture:
            capture.stop()
            return capture.captured

    def load_by_id(id: str):
        if not id:
            raise ValueError("Id value must be provided")
        _lib.ENGINE_load_builtin_engines()
        ptr = _lib.ENGINE_by_id(id.encode())
        if ptr == _NULL:
            raise ValueError("Could not load the {0} engine by id".format(id))
        return SSLEngine(ptr)

    def load_dynamic(
        id: str,
        path: str = None,
        search_path: str = None,
        check_version: bool = True,
    ):

        if not id:
            raise ValueError("Id value must be provided")

        dyn = SSLEngine.load_by_id("dynamic")
        dyn.ctrl_cmd_string("ID", id)

        if path:
            dyn.ctrl_cmd_string("SO_PATH", path)

        dyn.ctrl_cmd_string("LIST_ADD", 1)

        if not check_version:
            dyn.ctrl_cmd_string("NO_VCHECK", 1)

        if search_path == None and path == None and "OPENSSL_ENGINES" in os.environ:
            search_path = os.environ["OPENSSL_ENGINES"]

        if search_path:
            dyn.ctrl_cmd_string("DIR_LOAD", 2)
            dyn.ctrl_cmd_string("DIR_ADD", search_path)

        dyn.ctrl_cmd_string("LOAD")
        return dyn


def set_client_cert_engine(self: SSLContext, engine: "_ffi.CData | SSLEngine | str"):
    if not _lib.SSL_CTX_set_client_cert_engine(self._context, SSLEngine(engine).ptr):
        raise Exception("Was not able to set client cert engine")


SSLContext.set_client_cert_engine = set_client_cert_engine
