from abc import ABCMeta
from typing import OrderedDict, Sequence
from dukpy import JSInterpreter

class JSContextMeta(ABCMeta):
    def __new__(
        metaclass: "type[JSContext]",
        cls_name: str,
        base_classes: Sequence[object],
        cls_builder: OrderedDict[str, object],
    ):
        jsContext: "dict[str, object]" = cls_builder.pop("_JSCONTEXT", {})
        exclude: "list[str]" = cls_builder.get("_JSCONTEXT_EXCLUDE", [])
        for key, val in cls_builder.items():
            if key[0].isalpha():
                jsContext.setdefault(key, val)

        for cls in reversed(base_classes):
            exclude.extend(getattr(cls, "_JSCONTEXT_EXCLUDE", []))
            if hasattr(cls, "_JSCONTEXT"):
                update: dict = cls._JSCONTEXT
            else:
                update = {key: getattr(cls, key) for key in dir(cls) if key[0].isalpha()}
            for key, val in update.items():
                jsContext.setdefault(key, staticmethod(val))

        return type.__new__(
            metaclass,
            cls_name,
            base_classes,
            {
                **{
                    key: val
                    for key, val in cls_builder.items()
                    if not (key[0].isalpha() and key[0] not in exclude)
                },
                "_JSCONTEXT": {
                    key: val
                    for key, val in jsContext.items()
                    if (key[0].isalpha() and key[0] not in exclude)
                },
            },
        )


class JSContext(metaclass=JSContextMeta):
    def __init__(self, js:str) -> None:
        context:dict = object.__getattribute__(self, "_JSCONTEXT")
        engine = JSInterpreter()
        for key, val in context.items():
            if isinstance(val, staticmethod):
                val = val.__func__
            elif isinstance(val, classmethod):
                val = val.__get__(self.__class__)
            elif isinstance(val, property):
                raise Exception("Not supported yet")
            else:
                val = val.__get__(self)

            engine.export_function(key, val)
            _js = f"function {key}(){{ return call_python.apply(null, ['{key}'].concat(Array.prototype.slice.call(arguments))); }}"
            engine.evaljs(_js)
        engine.evaljs(js)

        object.__setattr__(self, "_jsengine", engine)

    def __getattribute__(self, name: str):
        engine:JSInterpreter = object.__getattribute__(self, "_jsengine")
        context:dict = object.__getattribute__(self, "_JSCONTEXT")
        if name in context:
            def jsFunction(*args):
                return engine.evaljs(f"{name}.apply(null, dukpy.args)", args = list(args))
            return jsFunction
        else:
            return object.__getattribute__(self, name)
