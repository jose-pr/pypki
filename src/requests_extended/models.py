from abc import abstractmethod, ABC
from sslcontext import SSLContext

class SSLContextMap(ABC):
    @abstractmethod
    def __getitem__(self, uri:str) -> 'SSLContext|None|bool|str':
        ...