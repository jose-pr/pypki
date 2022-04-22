# Based on https://stackoverflow.com/questions/24277488/in-python-how-to-capture-the-stdout-from-a-c-shared-library-to-a-variable
# TODO: ctypes / get_c_stream code missing source

from array import array
import ctypes
import os
import sys
import threading
import time

_WINDOWS = os.name == "nt"
_LIBC = ctypes.cdll.msvcrt if _WINDOWS else ctypes.CDLL(None)

if _WINDOWS:

    class _FILE__:
        _file: int

    class _FILE(ctypes.Structure):
        _fields_ = [
            ("_ptr", ctypes.c_char_p),
            ("_cnt", ctypes.c_int),
            ("_base", ctypes.c_char_p),
            ("_flag", ctypes.c_int),
            ("_file", ctypes.c_int),
            ("_charbuf", ctypes.c_int),
            ("_bufsize", ctypes.c_int),
            ("_tmpfname", ctypes.c_char_p),
        ]

    _IOB_FUNC = getattr(_LIBC, "__iob_func")
    _IOB_FUNC.restype = ctypes.POINTER(_FILE)
    _IOB_FUNC.argtypes = []


def get_c_stream(stream: "str|int") -> "tuple[int, ctypes.c_void_p]":
    if _WINDOWS:
        array: "list[_FILE__]" = _IOB_FUNC()
        if isinstance(stream, str):
            if stream == "stdout":
                i = 1
            elif stream == "stderr":
                i = 2
            elif stream == "stdin":
                i = 0
            else:
                raise ValueError("%s is not a valid c stream" % stream)
        else:
            i = 1
            while array[i]._file != 0:
                if array[i]._file == stream:
                    break
                i += 1
        file = array[i]
        return (file._file, ctypes.addressof(file))
    else:
        # Not complete
        try:
            return ctypes.c_void_p.in_dll(_LIBC, stream)
        except ValueError:
            return ctypes.c_void_p.in_dll(_LIBC, "_%sp" % stream)


def unbuffer_c_stream(ptr: int):
    if _WINDOWS:
        _IONBF = 4
    else:
        _IONBF = 2

    _LIBC.setvbuf.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_size_t,
    ]
    _LIBC.setvbuf(ptr, None, _IONBF, 0)


class FdOutputGrabber(object):
    """
    Class used to grab output of a fd stream.
    """

    def __init__(
        self,
        fd: "int | None" = None,
        escape_seq: "bytes | None" = None,
        timeout: float = .1,
        read_chunk: int = 4096,
    ):
        self.captured: bytes = b""
        self._bytes_captured = 0
        self.timeout = timeout
        self.escape_seq = escape_seq
        self.read_chunk = read_chunk
        self.fd, self._c_stream_ptr = get_c_stream("stdout" if fd is None else fd)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, type, value, traceback):
        self.stop()

    def _flush(self):
        if _WINDOWS:
            file_ptr = ctypes.c_void_p()
        else:
            file_ptr = self._c_stream_ptr
        _LIBC.fflush(file_ptr)

    def start(self):
        """
        Start capturing the stream data.
        """
        self.captured = b""
        self._bytes_captured = 0
        self.saved_fd = os.dup(self.fd)
        self.pipe_out, self.pipe_in = os.pipe()
        self._flush()
        unbuffer_c_stream(self._c_stream_ptr)
        os.dup2(self.pipe_in, self.fd)
        os.close(self.pipe_in)
        self.workerThread = threading.Thread(target=self.readOutput)
        self.workerThread.start()
        time.sleep(0.01)

    def stop(self, timeout: float = None):
        """
        Stop capturing the stream data and save it in `captured`.
        """
        timeout = timeout or self.timeout
        until = time.time() + timeout
        while True:
            _len = self._bytes_captured
            time.sleep(0.0001)
            if _len == self._bytes_captured:
                if time.time() <= until:
                    self._flush()
                else:
                    break
            else:
                until = time.time() + timeout
        os.close(self.fd)
        os.close(self.pipe_out)
        self.workerThread.join()
        self._flush()
        os.dup2(self.saved_fd, self.fd)
        os.close(self.saved_fd)

    def readOutput(self):
        """
        Read the stream data
        and save in `captured`.
        """
        while True:
            try:
                self.captured += os.read(self.pipe_out, self.read_chunk)
                if self.escape_seq is not None and self.captured.endswith(
                    self.escape_seq
                ):
                    self.captured = self.captured[: -len(self.escape_seq)]
                    self._bytes_captured -= len(self.escape_seq)
                    break
                self._bytes_captured = len(self.captured)
            except Exception:
                break
            time.sleep(0.0001)
