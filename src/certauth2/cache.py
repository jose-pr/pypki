# =================================================================
from abc import ABC, abstractmethod
from collections import OrderedDict
from io import FileIO
from pathlib import Path
import threading
from typing import Callable, Generic, Iterable, Literal, Sequence, TypeVar, overload
import os.path

K = TypeVar("K")
S = TypeVar("S")
T = TypeVar("T")
R = TypeVar("R")


class Cache(Generic[K, T, R]):
    def __contains__(self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False

    @abstractmethod
    def __setitem__(self, key: K, value: T) -> None:
        ...

    @abstractmethod
    def __getitem__(self, key: K) -> R:
        ...

    @overload
    def get(self, key: K) -> "R|None":
        ...

    @overload
    def get(self, key: K, default: Literal[None]) -> "R|None":
        ...

    def get(self, key: K, default: R = None):
        try:
            return self[key]
        except KeyError:
            return default


Transform = Callable[[T], R]


class FileCache(Cache[K, T, R]):
    def __init__(
        self,
        cache_dir: str,
        dump: Callable[[Iterable[FileIO], T], None],
        load: Callable[[Iterable[FileIO]], R],
        stored_as: Transform[K, Sequence[str]] = lambda x: [str(x)],
    ):
        self._lock = threading.Lock()
        self.cache_dir = Path(os.path.abspath(Path(cache_dir if cache_dir else "./")))
        self._dump = dump
        self._load = load
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self._stored_as = stored_as

    def stored_as(self, key: K):
        return [Path(os.path.abspath(self.cache_dir / f)) for f in self._stored_as(key)]

    def __contains__(self, key):
        filenames = self.stored_as(key)
        for file in filenames:
            if not file.exists():
                return False
        return True

    def __setitem__(self, key: K, value: T):
        filenames = self.stored_as(key)
        with self._lock:

            def _write():
                for file in filenames:
                    if self.cache_dir not in file.parents:
                        raise ValueError(f"Path is outside the store directory: {file}")
                    file.parent.mkdir(exist_ok=True, parents=True)
                    with file.open("wb") as fh:
                        yield fh

            self._dump(_write(), value)

    def __getitem__(self, key: K):
        filenames = self.stored_as(key)

        def _read():
            for file in filenames:
                if self.cache_dir not in file.parents:
                    raise ValueError(f"Path is outside the store directory: {file}")
                if not file.exists():
                    raise KeyError(key)
                with file.open("rb") as fh:
                    yield fh

        return self._load(_read())


class FileStorage(FileCache[K, T, R]):
    def __getitem__(self, key: K):
        return self.stored_as(key)

    def load(self, key: K):
        return super().__getitem__(key)


class LRUCache(Cache[K, T, R]):
    def __init__(self, max_size: int, transform: Transform[T, R] = lambda x: x):
        self._cache: "OrderedDict[S,R]" = OrderedDict()
        self.max_size = max_size
        self._transform = transform

    def __setitem__(self, key: K, item: T):
        self._cache[key] = self._transform(item)
        if len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

    def __getitem__(self, key: K):
        return self._cache[key]

    def __contains__(self, key):
        return key in self._cache
