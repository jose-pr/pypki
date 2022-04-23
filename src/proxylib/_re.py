ALPHA = r"A-Za-z"
DIGIT = r"0-9"
import re
SCHEME = rf"[{ALPHA}][{ALPHA}{DIGIT}+-.]*"
PORT = rf"[{DIGIT}]*"
NON_BREAKING = rf"[^:@/;]"
AUTHORITY = (
    rf"(?:({NON_BREAKING}*)(?::({NON_BREAKING}*))?@)?({NON_BREAKING}+)(?::({PORT}))?"
)
DELIM = r"(?:;|^)\s*"
_PAC_REGEX = re.compile(rf"{DELIM}({SCHEME})(?:\s+(?:{AUTHORITY})?\s*)")
_URI_REGEX = re.compile(rf"{DELIM}(?:(?:({SCHEME})://)?(?:{AUTHORITY})?\s*)")