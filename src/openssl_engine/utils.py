# https://stackoverflow.com/questions/24277488/in-python-how-to-capture-the-stdout-from-a-c-shared-library-to-a-variable

import os
import sys
import threading
import time


class FdOutputGrabber(object):
    """
    Class used to grab output of a fd stream.
    """

    def __init__(
        self,
        fd: int | None = None,
        escape_seq: bytes | None = None,
        timeout: float = 0.0001,
        read_chunk: int = 4096,
    ):
        self.fd = sys.stdout.fileno() if fd is None else fd
        self.captured: bytes = b""
        self._bytes_captured = 0
        self.timeout = timeout
        self.escape_seq = escape_seq
        self.read_chunk = read_chunk

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, type, value, traceback):
        self.stop()

    def start(self):
        """
        Start capturing the stream data.
        """
        self.captured = b""
        self._bytes_captured = 0
        self.pipe_out, self.pipe_in = os.pipe()
        self.saved_fd = os.dup(self.fd)
        os.dup2(self.pipe_in, self.fd)
        os.close(self.pipe_in)
        self.workerThread = threading.Thread(target=self.readOutput)
        self.workerThread.start()

    def stop(self, timeout: float = None):
        """
        Stop capturing the stream data and save it in `captured`.
        """
        timeout = timeout or self.timeout
        while True:
            _len = self._bytes_captured
            time.sleep(timeout)
            if _len == self._bytes_captured:
                os.close(self.fd)
                os.close(self.pipe_out)
                break

        self.workerThread.join()
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
