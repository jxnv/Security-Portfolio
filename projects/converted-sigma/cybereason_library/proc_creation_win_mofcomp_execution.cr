// Title: Potentially Suspicious Mofcomp Execution
// ID: 1dd05363-104e-4b4a-b963-196a534b03a1
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-12
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of the "mofcomp" utility as a child of a suspicious shell or script running utility or by having a suspicious path in the commandline.
// The "mofcomp" utility parses a file containing MOF statements and adds the classes and class instances defined in the file to the WMI repository.
// Attackers abuse this utility to install malicious MOF scripts
// Converted by: Sigma Universal SIEM/EDR CLI

(((((ParentImage="*\\cmd.exe" OR ParentImage="*\\powershell.exe" OR ParentImage="*\\pwsh.exe" OR ParentImage="*\\wsl.exe" OR ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe")) OR ((CommandLine contains "\\AppData\\Local\\Temp" OR CommandLine contains "\\Contacts\\" OR CommandLine contains "\\Favorites\\" OR CommandLine contains "\\Favourites\\" OR CommandLine contains "\\Music\\" OR CommandLine contains "\\Pictures\\" OR CommandLine contains "\\Users\\Public\\" OR CommandLine contains "\\Videos\\" OR CommandLine contains "\\WINDOWS\\Temp\\" OR CommandLine contains "%appdata%" OR CommandLine contains "%temp%" OR CommandLine contains "%tmp%"))) AND ((Image="*\\mofcomp.exe") OR (OriginalFileName == "mofcomp.exe"))) AND NOT (((ParentCommandLine="*\\InstallUtil.exe /Uninstall C:\\Windows\\CCM\\Microsoft.ConfigurationManager.SVProvider.dll" AND ParentImage="*\\InstallUtil.exe" AND (CommandLine contains "C:\\Windows\\TEMP" AND CommandLine contains ".tmp")) OR (ParentImage == "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" AND CommandLine contains "C:\\Windows\\TEMP\\" AND CommandLine="*.mof"))) AND NOT ((NOT ParentCommandLine=*)))
