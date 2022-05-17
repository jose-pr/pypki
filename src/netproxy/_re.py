ALPHA = r"A-Za-z"
DIGIT = r"0-9"
import re
SCHEME = rf"[{ALPHA}][{ALPHA}{DIGIT}+-.]*"
PORT = rf"[{DIGIT}]*"
NON_BREAKING = rf"[^:@/;]"
AUTHORITY = (
    rf"(?:({NON_BREAKING}*)(?::({NON_BREAKING}*))?@)?({NON_BREAKING}+)(?::({PORT}))?"
)
_URI_REGEX = re.compile(rf"(?:({SCHEME})://)?{AUTHORITY}(/.*)?")
_RULE_REGEX = re.compile(r"\s*([^\s]+)\s*(.*)")
_SPACE_REGEX = re.compile(r"\s*([^\s]+)\s*(.*)")