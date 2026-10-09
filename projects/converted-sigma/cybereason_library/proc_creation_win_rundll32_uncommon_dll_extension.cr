// Title: Rundll32 Execution With Uncommon DLL Extension
// ID: c3a99af4-35a9-4668-879e-c09aeb4f2bdf
// Status: test
// Level: medium
// Author: Tim Shelton, Florian Roth (Nextron Systems), Yassine Oukessou
// Date: 2022-01-13
// Tags: attack.stealth, attack.t1218.011
// Description: Detects the execution of rundll32 with a command line that doesn't contain a common extension
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\rundll32.exe") OR (OriginalFileName == "RUNDLL32.EXE")) AND NOT (((CommandLine == "") OR (((CommandLine contains ".cpl " OR CommandLine contains ".cpl," OR CommandLine contains ".cpl\"" OR CommandLine contains ".cpl'" OR CommandLine contains ".dll " OR CommandLine contains ".dll," OR CommandLine contains ".dll\"" OR CommandLine contains ".dll'" OR CommandLine contains ".inf " OR CommandLine contains ".inf," OR CommandLine contains ".inf\"" OR CommandLine contains ".inf'")) OR ((CommandLine="*.cpl" OR CommandLine="*.dll" OR CommandLine="*.inf"))) OR (CommandLine contains " -localserver ") OR (NOT CommandLine=*) OR (ParentImage="*\\msiexec.exe" AND (CommandLine contains ":\\Windows\\Installer\\" AND CommandLine contains ".tmp" AND CommandLine contains "zzzzInvokeManagedCustomActionOutOfProc")))) AND NOT (((ParentCommandLine contains ":\\Users\\" AND ParentCommandLine contains "\\AppData\\Local\\Microsoft\\EdgeUpdate\\Install\\{" AND ParentCommandLine contains "\\EDGEMITMP_" AND ParentCommandLine contains ".tmp\\setup.exe" AND ParentCommandLine contains "--install-archive=" AND ParentCommandLine contains "--previous-version=" AND ParentCommandLine contains "--msedgewebview --verbose-logging --do-not-launch-msedge --user-level"))))
