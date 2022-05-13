from abc import abstractmethod
from typing import AnyStr, Callable, Generic, OrderedDict, TypeVar
from x509creds import X509Credentials
from twisted.internet import ssl

K = TypeVar("K")
T = TypeVar("T")
R = TypeVar("R")
C = TypeVar("C")

TLS_PROTOCOLS = ["https", "ssl"]

def creds_into_twisted_format(creds:X509Credentials):
    key, cert, chain = creds.to_pyopenssl()
    cert = ssl.PrivateCertificate(cert)
    cert.privateKey = key
    return  cert, chain

def creds_into_twisted_options(creds:X509Credentials, **options):
    key, cert, chain = creds.to_pyopenssl()
    options.setdefault("fixBrokenPeers", True)
    options.setdefault("verify", False)
    return ssl.CertificateOptions(privateKey=key, certificate=cert, extraCertChain=chain, **options)

def get_at(arr:'list[T]', index: int, default:T = None):
    l = len(arr)
    return arr[index] if (-l <= index < l) else default
    
def as_str(src:AnyStr, encoding:str = "ascii"):
    return src.decode(encoding) if isinstance(src, bytes) else src

def as_bytes(src:AnyStr, encoding:str = "ascii"):
    return src.encode(encoding) if not isinstance(src, bytes) else src

class IFactory(Generic[K, T]):
    @abstractmethod
    def generate(self, key:K) -> T:
        ...

class SimpleFactory(IFactory[K, T]):
    def __init__(self, generator: Callable[[K],T]) -> None:
        self._generator = generator

    def generate(self, key: K) -> T:
        return self._generator(key)

class CachedFactory(IFactory[K, T], Generic[C, K, T]):
    def __init__(self, context:C, generator:Callable[[C,K], T], remove_hook: Callable[[C, T, K], None] = None, size_hint=1) -> None:
        self._context = context
        self._generator = generator
        self._remove_hook = remove_hook or (lambda *args, **kwds: None)
        self._cache:'OrderedDict[K, tuple[int,T]]' = OrderedDict()
        self._size_hint = size_hint

    def _get(self, key:K):
        self.clean(self._size_hint -1)
        (cnt, item) = self._cache.get(key, (-1, None))
        if cnt == -1: 
            cnt = 0
            item = self._generator(self._context, key)
            self._cache[key] = (0, item)
        return cnt, item

    def generate(self, key: K) -> T:
        return self._get(key)[1]

    def remove(self, key:K):
        if key in self._cache:
            cnt, item = self._cache.pop(key)
            self._remove_hook(self._context, item, key)

    def __getitem__(self, key:K):
        return self.generate(key)
    
    def setdefault(self, key:K, default:T):
        self.clean(self._size_hint - 1)
        return self._cache.setdefault(key, (0, default))[1]

    def use(self, key:K):
        cnt, item = self._cache.pop(key, (None, None))
        if cnt is None:
             cnt = 0
             item =  self._generator(self._context, key)
        self._cache[key] = (cnt+1, item)
        self.clean()
        return item

    def done(self, key: K):
        cnt, item = self._cache.pop(key, (None, None))
        if cnt is not None:
            if cnt > 0:
                self._cache[key] = (cnt-1, item)
            else:
                self._cache[key] = (0, item)

        self.clean()

    def clean(self, size_hint:int = None):
        if size_hint is None:
            size_hint = self._size_hint

        for key in self._cache.keys():
            if size_hint >= len(self._cache):
                break
            
            cnt, item = self._cache[key]
            if not cnt:
                self._cache.pop(key)
                self._remove_hook(self._context, item, key)
