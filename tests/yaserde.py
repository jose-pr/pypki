
import json_stream
import json
from io import BytesIO
import sys

from src.yaserde.serde import Struct

test = {
    "results": [{"test": 1, "test2": {"name": "test", "name2": ["test2", "test3"]}}, 2],
    "meta": {"test": [1, 24], "meta2":"someclass"},
    "meta2":10,
    "items":"test"

}

test_str = json.dumps(test)
src = BytesIO(test_str.encode())

stream = json_stream.load(src)


class WithError(Struct):
    meta2:int
    pass
class WithError2(WithError):
    items:str
print("done1")
test3 = WithError2(stream)
print("done2")
test4 = WithError()
pass
