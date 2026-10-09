# Title: Powershell Timestomp
# ID: c6438007-e081-42ce-9483-b067fbef33c3
# Status: test
# Level: medium
# Author: frack113
# Date: 2021-08-03
# Tags: attack.stealth, attack.t1070.006
# Description: Adversaries may modify file time attributes to hide new or changes to existing files.
# Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Powershell Timestomp
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*.CreationTime =*" OR ScriptBlockText="*.LastWriteTime =*" OR ScriptBlockText="*.LastAccessTime =*" OR ScriptBlockText="*[IO.File]::SetCreationTime*" OR ScriptBlockText="*[IO.File]::SetLastAccessTime*" OR ScriptBlockText="*[IO.File]::SetLastWriteTime*"))
    return True

def title(event):
    return "Powershell Timestomp"

