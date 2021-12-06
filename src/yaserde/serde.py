from __future__ import annotations
from copy import deepcopy
import inspect
from typing import Iterable, OrderedDict, Sequence, get_type_hints, Type
from typing_extensions import Self


from .utils import (
    T,
    R,
    StructLike,
    is_dunder,
    is_private,
    make_private,
    map_iter_to_list,
    dictcopy,
)
from .factory import (
    MissingAttributeError,
    ParseOptions,
    ParseAttributeError,
    ParseError,
    TypeFactory,
    TypeFactoryContext,
)

import re

NOT_ALLOWED_IN_ID = re.compile("[^a-zA-Z0-9_]")


class MetaStruct(type):
    @staticmethod
    def get_key(cls: Type[Struct], name: str) -> str:
        qname, factory = cls.__ATTR_FACTORIES__.get(name, (None, None))
        return qname if qname else name

    @staticmethod
    def get_factories(cls: Type[Struct]) -> OrderedDict[str, (str, TypeFactory)]:
        return cls.__ATTR_FACTORIES__

    def __new__(
        metacls: MetaStruct, cls_name: str, bases: Sequence[Type], dctn: dict[str]
    ):
        _hints: list[(str, (str, Type))] = []
        dctn["__slots__"] = tuple()
        dctn["__ATTR_FACTORIES__"] = OrderedDict()
        object_hook = None
        methods: list[str] = map_iter_to_list(lambda k: k, dctn.keys())
        for cls in bases:
            methods.extend(
                map_iter_to_list(
                    lambda m: m[0],
                    inspect.getmembers(cls),
                )
            )
            object_hook = getattr(cls, "factory_struct_hook", None)
            _hints.extend(getattr(cls, "__ATTR_FACTORIES__", {}).items())

        object_hook = dctn.get("factory_struct_hook", object_hook)
        _hints.extend(
            (
                (name, (None, hint))
                for name, hint in dctn.get("__annotations__", {}).items()
            )
        )
        for pos, name, hint in dctn.get("__EXTRA_HINTS__", []):
            _hints.insert(pos, (name, (None, hint)))

        methods = set(methods)
        for name, (escaped, hint) in _hints:
            if escaped is None:
                escaped = re.sub(NOT_ALLOWED_IN_ID, "_", name).lstrip('_')

                while escaped in dctn["__slots__"] or escaped in methods:
                    escaped += "_"

                dctn["__slots__"] += (escaped,)
                #escaped = f"_{cls_name}{escaped}"

            dctn["__ATTR_FACTORIES__"][name] = (
                escaped,
                (
                    hint
                    if isinstance(hint, TypeFactory)
                    else TypeFactory(hint, object_hook=object_hook)
                ),
            )

        return type.__new__(metacls, cls_name, bases, dctn)


class Struct(metaclass=MetaStruct):
    def __new__(cls, *srcs: object, **src):
        options = ParseOptions()
        for src in srcs or [{}]:
            if not isinstance(src, ParseOptions):
                if src.__class__ is cls and not options.copy:
                    return src
                break
            else:
                options = src

        return object.__new__(cls)

    def __init__(self, *srcs, **src) -> None:
        cls: Type[Struct] = object.__getattribute__(self, "__class__")
        options = ParseOptions()
        depth = options.next().copy
        for src in [*srcs, src]:
            if isinstance(src, ParseOptions):
                options = src
                depth = options.next().copy
            else:
                cls.update(self, src, depth)

    def __contains__(self, key: str):
        cls: Type[Struct] = object.__getattribute__(self, "__class__")
        return key in MetaStruct.get_factories(cls)

    def __getitem__(self, key: str):
        return getattr(self, key)

    def get(self, key: str, default: T = None) -> T:
        return getattr(self, key, default)

    def __dir__(self):
        cls: Type[Struct] = object.__getattribute__(self, "__class__")
        for key in MetaStruct.get_factories(cls):
            yield key

    def items(self):
        cls: Type[Struct] = object.__getattribute__(self, "__class__")
        for key in MetaStruct.get_factories(cls):
            try:
                yield key, getattr(self, key)
            except:
                pass

    @staticmethod
    def factory_struct_hook(factory: TypeFactory, src: object, options: ParseOptions):
        return (
            factory.type(options, src)
            if issubclass(factory.type, Struct)
            else factory.type(src)
        )

    def __setitem__(self, name: str, value, copy_depth: int = 0):
        cls: Type[Struct] = object.__getattribute__(self, "__class__")
        escaped, factory = MetaStruct.get_factories(cls).get(name, (None, None))
        if factory:
            cls.__setattr__(self, name, factory(value, ParseOptions(copy_depth)))

    def __getattribute__(self, key: str):
        cls: Type[Struct] = object.__getattribute__(self, "__class__")
        return object.__getattribute__(self, MetaStruct.get_key(cls, key))

    def __setattr__(self, name: str, value) -> None:
        cls: Type[Struct] = object.__getattribute__(self, "__class__")
        object.__setattr__(self, MetaStruct.get_key(cls, name), value)

    def __delitem__(self, key: str):
        cls: Type[Struct] = object.__getattribute__(self, "__class__")
        super().__delitem__(self, MetaStruct.get_key(cls, key))

    def __copy__(self):
        cls: Type[Struct] = object.__getattribute__(self, "__class__")
        clone = cls.__new__(cls)
        for name, value in cls.items(self):
            setattr(clone, name, value)
        return clone

    def __deepclone__(self, memo):
        cls: Type[Struct] = object.__getattribute__(self, "__class__")
        clone = cls.__new__(cls)
        memo[id(self)] = clone
        for name, value in cls.items(self):
            setattr(clone, name, deepcopy(value, memo))
        return clone

    @classmethod
    def validate_value(cls, value: object):
        if isinstance(value, ParseError):
            raise value
        elif isinstance(value, Struct):
            value.__class__.validate(value)
        elif isinstance(value, list):
            for val in value:
                cls.validate_value(val)

    @classmethod
    def validate(cls, obj: StructLike) -> Self:
        obj = cls(ParseOptions(0), obj)
        for attr in MetaStruct.get_factories(cls):
            try:
                value = getattr(obj, attr)
                cls.validate_value(value)
            except AttributeError as e:
                raise MissingAttributeError([attr])
            except MissingAttributeError as e:
                raise MissingAttributeError([attr, *e.attr])
            except ParseAttributeError as e:
                raise ParseAttributeError(e.item, e.error, [attr, *e.attr])
            except ParseError as e:
                raise ParseAttributeError(e.item, e.error, [attr])
        return obj

    def update(
        self,
        struct: StructLike,
        copy_depth: int = 0,
    ) -> None:
        if struct is not self:
            for prop, value in struct.__class__.items(struct):
                self.__class__.__setitem__(self, prop, value, copy_depth)
            pass
