import os, sys
from pathlib import Path

USER_HOME = Path(os.environ.get("USER_HOME", Path.home()))
DEFAULT_PROXY_PATH = USER_HOME / ".netproxy"