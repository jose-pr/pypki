import argparse
import sys, os, shutil
from pathlib import Path

_local_dir = Path(__file__).parent.resolve()

default_config = _local_dir / "netproxy.toml"
_parent = str(_local_dir.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)
__package__ = _local_dir.name

sys.path.insert(0, str(_local_dir / "extern"))

from .constants import DEFAULT_PROXY_PATH
from .context import NetProxy


def start(args=None):
    parser = argparse.ArgumentParser(
        description="NetProxy is a configurable http and reverse proxy"
    )
    parser.add_argument(
        "-c", "--config", dest="config", help="Path to configuration file"
    )
    parser.add_argument(
        "--home", dest="home", help="Path to home directory for NetProxy"
    )
    args = parser.parse_args(args)
    _home = args.home if args.home else DEFAULT_PROXY_PATH
    config = Path(
        args.config
        if args.config
        else os.environ.get("NETPROXY_CONFIG", _home / "config.toml")
    )
    if default_config.exists() and not config.exists():
        if not config.parent.exists():
            config.parent.mkdir(exist_ok=True, parents=True)
        shutil.copy(default_config, config)
    
    netproxy = NetProxy(home=args.home, config=config)
    netproxy.listen()
    netproxy.reactor.run()

if __name__ == "__main__":
    try:
        start()
    except Exception as e:
        print(e)
    input("Press any key to close")
