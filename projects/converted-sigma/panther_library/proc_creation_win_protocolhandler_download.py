# Title: File Download Using ProtocolHandler.exe
# ID: 104cdb48-a7a8-4ca7-a453-32942c6e5dcb
# Status: test
# Level: medium
# Author: frack113
# Date: 2021-07-13
# Tags: attack.stealth, attack.t1218
# Description: Detects usage of "ProtocolHandler" to download files. Downloaded files will be located in the cache folder (for example - %LOCALAPPDATA%\Microsoft\Windows\INetCache\IE)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: File Download Using ProtocolHandler.exe
def rule(event):
    # Detection Logic:
    # (((CommandLine="*ftp://*" OR CommandLine="*http://*" OR CommandLine="*https://*")) AND ((Image="*\\protocolhandler.exe") OR (OriginalFileName="ProtocolHandler.exe")))
    return True

def title(event):
    return "File Download Using ProtocolHandler.exe"

