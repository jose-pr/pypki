# =================================================================
from abc import ABC, abstractmethod
from collections import OrderedDict
from pathlib import Path
import threading
from typing import Callable, Generic, Iterable, Sequence, TypeVar, overload

K = TypeVar("K")
S = TypeVar("S")
T = TypeVar("T")
R = TypeVar("R")


class Cache(Generic[K, S, T, R]):
    @abstractmethod
    def __setitem__(self, key: K, value: T) -> None:
        ...

    @abstractmethod
    def __getitem__(self, key: K) -> R:
        ...

    @overload
    def get(self, key: K) -> None:
        ...

    def get(self, key: K, default: R = None):
        try:
            return self[key]
        except KeyError:
            return default

    def stored_as(self, key: K) -> S:
        return key


Transform = Callable[[T], R]


class FileCache(Cache[K, Path, T, R]):
    def __init__(
        self,
        cache_dir: str,
        as_bytes: Transform[T, Sequence[bytes]],
        from_bytes: Transform[Sequence[bytes], R],
        stored_as: Transform[K, Sequence[str]] = lambda x: [str(x)],
    ):
        self._lock = threading.Lock()
        self.cache_dir = Path(cache_dir if cache_dir else "./")
        self.modified = False
        self.as_bytes = as_bytes
        self.from_bytes = from_bytes
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self._stored_as = stored_as

    def stored_as(self, key: K):
        return [self.cache_dir.joinpath(f) for f in self._stored_as(key)]

    def __setitem__(self, key: K, value: T):
        filenames = self.stored_as(key)
        with self._lock:
            for i, data in enumerate(self.as_bytes(value)):
                filenames[i].write_bytes(data)
                self.modified = True

    def __getitem__(self, key: K):
        filenames = self.stored_as(key)
        data = []
        def _read():
            for file in filenames:
                if not file.exists():
                    raise KeyError(key)
                yield file.read_bytes()
        return self.from_bytes(_read())


class LRUCache(Cache[K, S, T, R]):
    def __init__(
        self,
        max_size: int,
        transform: Transform[T, R] = lambda x: x,
        stored_as: Transform[K, S] = lambda x: x,
    ):
        self._cache: "OrderedDict[S,R]" = OrderedDict()
        self.max_size = max_size
        self._stored_as = stored_as
        self._transform = transform

    def stored_as(self, key: K):
        return self._stored_as(key)

    def __setitem__(self, key: K, item: T):
        key = self._stored_as(key)
        self._cache[key] = self._transform(item)
        if len(self._cache) > self.max_size:
            self._cache.popitem(last=False)
