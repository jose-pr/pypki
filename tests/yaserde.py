
import json_stream
import json
from io import BytesIO
import sys
from sys import getsizeof
from src.yaserde.serde import Struct

test = {
    "meta2":10,
    "items":"test",
    "@test1":"test2",
    "_test1":"test3",
    "__test1__":"test4"
}

test_str = json.dumps(test)
src = BytesIO(test_str.encode())

stream = json_stream.load(src)


class WithError(Struct):
    meta2:int
    meta3:str
    meta4:str
    __EXTRA_HINTS__ = [
        (0, "@test1", str),
        (0, "_test1", str),
        (0, "__test1", str),
        (0, "__test1__", str)

    ]
    pass
class WithError2(WithError):
    items:str
print("done1")
test3 = WithError2(stream)
print("done2")
test4 = WithError()
items=dict(test3.__class__.items(test3))
test3.validate(test3)
pass
