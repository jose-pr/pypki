from typing import ClassVar, Literal, Mapping, Sequence, Type, TypedDict
from typing_extensions import Self, TypeAlias

Value: TypeAlias = "Literal['None']|str|int|float"
StructLike: TypeAlias = "Mapping[str, ObjectLike]"
ArrayLike: TypeAlias = "Sequence[ObjectLike]"
ObjectLike: TypeAlias = "Value|StructLike|ArrayLike"


class _EMPTY_ARG:
    ...

_EMPTY_ARG_INST = _EMPTY_ARG()

class FactoryClass:
    __TYPES: 'ClassVar[dict[str,Type]]'
    __TYPE_PROP__: ClassVar[str] = "__class__"

    @classmethod
    def _get_type(cls, src:StructLike) -> str:
        return src.get(cls.__TYPE_PROP__, "")
    @classmethod
    def _normalize_src(cls, src: ObjectLike) -> StructLike:
        return src

    def  __new__(cls: 'type[Self]', __src:ObjectLike = _EMPTY_ARG_INST, /, **fields:ObjectLike) -> 'Self':
        register:'dict[str, type[Self]]' = getattr(cls, f"_{cls.__name__}__TYPES", {"": cls})       
        fields = cls._normalize_src(__src if __src != _EMPTY_ARG_INST else fields)
        type = cls._get_type(fields) or ""
        cls = register.get(type, cls)
        inst = super().__new__(cls)
        inst.__init__(**fields)
        return inst

    def __init__(self,__src:ObjectLike = _EMPTY_ARG_INST, /, **fields:ObjectLike) -> None:
        _ignore = self.__TYPE_PROP__
        for prop, value in fields.items():
            if _ignore != prop:
                setattr(self, prop, value)

    @classmethod
    def register(cls, type:Type[Self], is_default:bool = False):
        prop = f"_{cls.__name__}__TYPES"
        register:'dict[str, type[Self]]' = getattr(cls, prop, None)
        if register is None:
            register = {"":cls}
            setattr(cls, prop, register)
        register[getattr(type, cls.__TYPE_PROP__)] = type
        if is_default:
            register[""] = type


