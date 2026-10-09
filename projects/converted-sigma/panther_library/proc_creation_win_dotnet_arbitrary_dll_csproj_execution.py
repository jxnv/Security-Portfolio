# Title: Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE
# ID: d80d5c81-04ba-45b4-84e4-92eba40e0ad3
# Status: test
# Level: medium
# Author: Beyu Denis, oscd.community
# Date: 2020-10-18
# Tags: attack.stealth, attack.t1218
# Description: Detects execution of arbitrary DLLs or unsigned code via a ".csproj" files via Dotnet.EXE.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE
def rule(event):
    # Detection Logic:
    # ((((CommandLine="*.csproj" OR CommandLine="*.csproj\"" OR CommandLine="*.dll" OR CommandLine="*.dll\"" OR CommandLine="*.csproj'" OR CommandLine="*.dll'")) AND ((Image="*\\dotnet.exe") OR (OriginalFileName=".NET Host"))) AND NOT (((ParentImage="C:\\Program Files (x86)\\Notepad++\\notepad++.exe" OR ParentImage="C:\\Program Files\\Notepad++\\notepad++.exe") AND (CommandLine="*C:\\ProgramData\\CSScriptNpp\\*" AND CommandLine="*-cscs_path:*" AND CommandLine="*\\cs-script\\cscs.dll*"))))
    return True

def title(event):
    return "Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE"

