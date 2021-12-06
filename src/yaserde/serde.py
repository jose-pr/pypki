from __future__ import annotations
from copy import deepcopy
import inspect
from typing import Iterable, OrderedDict, Sequence, get_type_hints, Type
from typing_extensions import Self


from .utils import T, R, StructLike, map_iter_to_list, dictcopy
from .factory import ParseOptions, ParseAttributeError, ParseError, TypeFactory, TypeFactoryContext

class MetaStruct(type):

    @staticmethod
    def escape_name(name:str):
        return f"__{name}"
    @staticmethod
    def get_key(cls:Type[Struct], name:str):
        qname = cls.__ATTR_MAP__.get(name, None)
        return f"_{cls.__name__}{qname}" if qname else name

    def __new__(metacls:MetaStruct, cls_name:str, bases:Sequence[Type], dctn:dict[str]):
        _hints:list[(str, Type)] = []
        dctn["__slots__"] = tuple()
        dctn['__ATTR_FACTORIES__'] = OrderedDict()
        object_hook = None
        methods:list[str] = list(dctn.keys())
        for cls in bases:
            methods.extend(map_iter_to_list(lambda m: m[0], inspect.getmembers(cls, predicate=inspect.isfunction)))
            object_hook = getattr(cls, 'factory_struct_hook', None)
            _hints.extend(getattr(cls, '__ATTR_FACTORIES__', {}).items())

        object_hook = dctn.get('factory_struct_hook', object_hook)
        _hints.extend(dctn.get("__annotations__", {}).items())
        for pos, name, hint  in dctn.get('__EXTRA_HINTS__', []):
            _hints.insert(pos, (name, hint))

        dctn["__ATTR_MAP__"] = {}
        for name, hint in _hints:
            dctn['__ATTR_FACTORIES__'][name] = hint if isinstance(hint, TypeFactory) else TypeFactory(hint, object_hook=object_hook)
            if name not in dctn["__slots__"]:
                if name in methods:
                    escaped = metacls.escape_name(name)
                    dctn["__ATTR_MAP__"][name] = escaped
                    name = escaped
                dctn["__slots__"] += (name,)

        return type.__new__(metacls, cls_name, bases, dctn)

class Struct(metaclass = MetaStruct):
    __EXTRA_HINTS__ = []
    def __new__(cls, *srcs:object, **src):
        options = ParseOptions()
        for src in srcs or [{}]:
            if not isinstance(src, ParseOptions):
                if src.__class__ is cls and not options.copy:
                    return cls
                break
            else:
                options = src

        obj = object.__new__(cls)
        return obj


    def __init__(self, *srcs, **src) -> None:
        cls:Type[Struct] = object.__getattribute__(self, '__class__')
        options = ParseOptions()
        depth = options.next().copy
        for src in [*srcs, src]:
            if isinstance(src, ParseOptions):
                options = src
                depth = options.next().copy
            else:
                cls.update(self, src, depth)
            
    def __contains__(self, key:str):
        cls:Type[Struct] = object.__getattribute__(self, '__class__')
        return key in cls.__ATTR_FACTORIES__

    def __getitem__(self, key:str):
        return  getattr(self, key)

    def get(self, key:str, default:T = None) -> T:
        return  getattr(self,  key, default)

    def items(self):
        cls:Type[Struct] = object.__getattribute__(self, '__class__')
        for key in cls.__ATTR_FACTORIES__:
            yield key, getattr(self, key)

    @staticmethod
    def factory_struct_hook(factory:TypeFactory, src:object, options:ParseOptions):
        return  factory.type(options, src) if issubclass(factory.type, Struct) else factory.type(src)
          
    def __setitem__(self, name:str, value, copy_depth:int = 0):
        cls:Type[Struct] = object.__getattribute__(self, '__class__')
        factory =  cls.__ATTR_FACTORIES__.get(name, None)
        if factory:
            cls.__setattr__(self, name, factory(value, ParseOptions(copy_depth)))
       
    def __getattribute__(self, key: str):
        cls:Type[Struct] = object.__getattribute__(self, '__class__')
        return  object.__getattribute__(self, MetaStruct.get_key(cls, key))

    def __setattr__(self, name: str, value) -> None:
        cls:Type[Struct] = object.__getattribute__(self, '__class__')
        object.__setattr__(self, MetaStruct.get_key(cls, name), value)

    def __delitem__(self, key:str):
        cls:Type[Struct] = object.__getattribute__(self, '__class__')
        super().__delitem__(self,  MetaStruct.get_key(cls, key))


    def __copy__(self):
        cls:Type[Struct] = object.__getattribute__(self, '__class__')
        clone = cls.__new__(cls)
        for name, value in cls.items(self):
            setattr(clone, name, value)            
        return clone

    def __deepclone__(self, memo):
        cls:Type[Struct] = object.__getattribute__(self, '__class__')
        clone = cls.__new__(cls)
        memo[id(self)] = clone
        for name, value in cls.items(self):
            setattr(clone, name, deepcopy(value, memo))  
        return clone

    @classmethod
    def validate_value(cls, value:object):
        if isinstance(value, ParseError):
            raise value
        elif isinstance(value, Struct):
            value.__class__.validate(value)
        elif isinstance(value, list):
            for val in value:
                cls.validate_value(val)

    @classmethod
    def validate(cls, obj:StructLike) -> Self:
        obj = cls(ParseOptions(0), obj)
        for attr, value in obj.__dict__.items():
            try:
                cls.validate_value(value)
            except ParseAttributeError as e:
                raise ParseAttributeError(e.item, e.error, [attr, *e.attr])
            except ParseError as e:
                raise ParseAttributeError(e.item, e.error, [attr])
        return obj

    def update(
        self,
        struct: StructLike,
        copy_depth:int = 0,
    ) -> None:
        if struct is not self:
            for prop, value in struct.__class__.items(struct):
                self.__class__.__setitem__(self, prop, value, copy_depth)
            pass
