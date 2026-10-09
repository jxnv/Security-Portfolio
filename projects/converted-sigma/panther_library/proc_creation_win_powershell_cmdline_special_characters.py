# Title: Potential PowerShell Command Line Obfuscation
# ID: d7bcd677-645d-4691-a8d4-7a5602b780d1
# Status: test
# Level: high
# Author: Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton (fp)
# Date: 2020-10-15
# Tags: attack.execution, attack.stealth, attack.t1027, attack.t1059.001
# Description: Detects the PowerShell command lines with special characters
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential PowerShell Command Line Obfuscation
def rule(event):
    # Detection Logic:
    # (((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll"))) AND ((CommandLine=regex("\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+")) OR (CommandLine=regex("\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{")) OR (CommandLine=regex("\\^.*\\^.*\\^.*\\^.*\\^")) OR (CommandLine=regex("`.*`.*`.*`.*`")))) AND NOT (((ParentImage="C:\\Program Files\\Amazon\\SSM\\ssm-document-worker.exe") OR ((CommandLine="*new EventSource(\"Microsoft.Windows.Sense.Client.Management\"*" OR CommandLine="*public static extern bool InstallELAMCertificateInfo(SafeFileHandle handle);*")))))
    return True

def title(event):
    return "Potential PowerShell Command Line Obfuscation"

