import winreg as _reg
from .common import  EnvProxyConfig
from ..utils import SingleProxyMap
def _queryvalue(key:_reg.HKEYType, subkey:str)->str:
    try:
        value, type = _reg.QueryValueEx(key, subkey)
        return value
    except:
        return None

_WINREG_INTERNET_SETTINGS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"

def system_proxy():
    settings = _reg.OpenKey(_reg.HKEY_CURRENT_USER, _WINREG_INTERNET_SETTINGS)
    pac = _queryvalue(settings, "AutoConfigURL")
    if pac:
        return pac
    if _queryvalue(settings, "ProxyEnable"):
        env_proxy = _queryvalue(settings, "ProxyServer")
        overrides = _queryvalue(settings, "ProxyOverride")
        if env_proxy:
            return EnvProxyConfig(env_proxy, env_proxy, overrides.split(";") if overrides else [] )
    
    if _queryvalue(settings, "EnableNegotiate"):
        #TODO
        pass
    return SingleProxyMap()

