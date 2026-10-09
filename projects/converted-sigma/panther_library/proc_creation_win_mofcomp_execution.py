# Title: Potentially Suspicious Mofcomp Execution
# ID: 1dd05363-104e-4b4a-b963-196a534b03a1
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-12
# Tags: attack.stealth, attack.t1218
# Description: Detects execution of the "mofcomp" utility as a child of a suspicious shell or script running utility or by having a suspicious path in the commandline.
# The "mofcomp" utility parses a file containing MOF statements and adds the classes and class instances defined in the file to the WMI repository.
# Attackers abuse this utility to install malicious MOF scripts
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potentially Suspicious Mofcomp Execution
def rule(event):
    # Detection Logic:
    # (((((ParentImage="*\\cmd.exe" OR ParentImage="*\\powershell.exe" OR ParentImage="*\\pwsh.exe" OR ParentImage="*\\wsl.exe" OR ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe")) OR ((CommandLine="*\\AppData\\Local\\Temp*" OR CommandLine="*\\Contacts\\*" OR CommandLine="*\\Favorites\\*" OR CommandLine="*\\Favourites\\*" OR CommandLine="*\\Music\\*" OR CommandLine="*\\Pictures\\*" OR CommandLine="*\\Users\\Public\\*" OR CommandLine="*\\Videos\\*" OR CommandLine="*\\WINDOWS\\Temp\\*" OR CommandLine="*%appdata%*" OR CommandLine="*%temp%*" OR CommandLine="*%tmp%*"))) AND ((Image="*\\mofcomp.exe") OR (OriginalFileName="mofcomp.exe"))) AND NOT (((ParentCommandLine="*\\InstallUtil.exe /Uninstall C:\\Windows\\CCM\\Microsoft.ConfigurationManager.SVProvider.dll" AND ParentImage="*\\InstallUtil.exe" AND (CommandLine="*C:\\Windows\\TEMP*" AND CommandLine="*.tmp*")) OR (ParentImage="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" AND CommandLine="*C:\\Windows\\TEMP\\*" AND CommandLine="*.mof"))) AND NOT ((NOT ParentCommandLine=*)))
    return True

def title(event):
    return "Potentially Suspicious Mofcomp Execution"

