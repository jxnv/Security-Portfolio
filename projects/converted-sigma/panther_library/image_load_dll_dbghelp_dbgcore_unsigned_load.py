# Title: Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded
# ID: bdc64095-d59a-42a2-8588-71fd9c9d9abc
# Status: test
# Level: high
# Author: Perez Diego (@darkquassar), oscd.community, Ecco
# Date: 2019-10-27
# Tags: attack.credential-access, attack.t1003.001
# Description: Detects the load of dbghelp/dbgcore DLL (used to make memory dumps) by suspicious processes.
# Tools like ProcessHacker and some attacker tradecract use MiniDumpWriteDump API found in dbghelp.dll or dbgcore.dll.
# As an example, SilentTrynity C2 Framework has a module that leverages this API to dump the contents of Lsass.exe and transfer it over the network back to the attacker's machine.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded
def rule(event):
    # Detection Logic:
    # ((ImageLoaded="*\\dbghelp.dll" OR ImageLoaded="*\\dbgcore.dll") AND Signed="false")
    return True

def title(event):
    return "Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded"

