from copy import deepcopy
from typing import Callable, Iterable, MutableMapping, Mapping, Sequence, TypeGuard, TypeVar, Type
from typing_extensions import Self


T = TypeVar("T")
R = TypeVar("R")

Value = None | str | int | float
StructLike = Mapping[str, 'Object' ]
ArrayLike = Sequence['Object'] 
Object = Value | StructLike | ArrayLike

MapFn = Callable[[T], R]

def dictcopy(src:Mapping, dest:MutableMapping, memo:dict):
    for prop, obj in src.items():
        dest[prop] = deepcopy(obj, memo)

def map_iter_to_list(fn: MapFn, src: Iterable[T]):
    return [fn(val) for val in src]

def get_or(self:list[T], index:int, default:T = None) -> T:
    l = len(self)
    return self[index] if -l <= index < l else default

def subclasses(cls:Type) -> Iterable[Type]:
    for subclass in cls.__subclasses__():
        yield from  subclasses(subclass)
        yield subclass