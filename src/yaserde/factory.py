from types import NoneType
from typing import Iterable, MutableMapping, Type, Generic, Callable, get_args
from typing_extensions import Self
from .utils import T, R


class ParseOptions:
    def __init__(self, copy: int = 1) -> None:
        self.copy = copy

    def next(self):
        return ParseOptions(self.copy - 1 if self.copy > 0 else self.copy)


class ParseError(Exception):
    def __init__(self, item, error) -> None:
        self.item = item
        self.error = error

class MissingAttributeError(ParseError):
    def __init__(self, attr) -> None:
        self.attr = attr
        super().__init__(None, None)


class ParseAttributeError(ParseError):
    def __init__(self, item, error, attr) -> None:
        self.attr = attr
        super().__init__(item, error)


TypeFactoryContext = MutableMapping[int, "TypeFactory"]


class TypeFactory(Generic[T, R]):
    type: Type[T]
    context: TypeFactoryContext

    def __new__(cls, type, context: TypeFactoryContext = None, object_hook=None):
        _id = id(type)

        if not context or _id not in context:
            factory = object.__new__(cls)
            factory.context = context or {}
            factory.context[_id] = factory
        else:
            factory = context[_id]

        return factory

    def __init__(
        self,
        type: Type[T],
        context: TypeFactoryContext = None,
        object_hook: Callable[[Self, R, ParseOptions], T] = None,
    ) -> None:
        self.type = type
        self.args = TypesFactory(get_args(type), self.context)
        if object_hook:
            self.__objecthook__ = object_hook

        if type is NoneType:
            self._call = TypeFactory._none
        elif issubclass(self.type, list):
            self._call = TypeFactory._list
        else:
            self._call = TypeFactory._objecthook

    def _list(self, iter: Iterable, options: ParseOptions):
        return self._objecthook((self.args(val, options) for val in iter), options)

    def _none(self, arg, options):
        if arg is not None:
            raise ValueError("None can only be created from None", arg)
        return None

    def _objecthook(self, value, options: ParseOptions):
        return self.type(value)

    def __call__(self, value: R, options: ParseOptions) -> T:
        try:
            return self._call(self, value, options)
        except Exception as _e:
            return ParseError(value, [_e])


class TypesFactory:
    def __init__(
        self, types: list[TypeFactory], context: TypeFactoryContext = None
    ) -> None:
        self.context: dict[int, TypeFactory] = context or {}
        self.types = [TypeFactory(type, context) for type in types]

    def __call__(self, item: object, options: ParseOptions):
        errors = []
        for factory in self.types:
            try:
                return factory(item, options)
            except Exception as _e:
                errors.append(_e)
                continue
        return ParseError(item, errors)
