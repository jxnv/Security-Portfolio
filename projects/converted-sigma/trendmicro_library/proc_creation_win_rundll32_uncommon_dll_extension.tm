// Title: Rundll32 Execution With Uncommon DLL Extension
// ID: c3a99af4-35a9-4668-879e-c09aeb4f2bdf
// Status: test
// Level: medium
// Author: Tim Shelton, Florian Roth (Nextron Systems), Yassine Oukessou
// Date: 2022-01-13
// Tags: attack.stealth, attack.t1218.011
// Description: Detects the execution of rundll32 with a command line that doesn't contain a common extension
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\rundll32.exe") OR (OriginalFileName: "RUNDLL32.EXE")) AND NOT (((CommandLine: "") OR (((CommandLine: "*.cpl *" OR CommandLine: "*.cpl,*" OR CommandLine: "*.cpl\"*" OR CommandLine: "*.cpl'*" OR CommandLine: "*.dll *" OR CommandLine: "*.dll,*" OR CommandLine: "*.dll\"*" OR CommandLine: "*.dll'*" OR CommandLine: "*.inf *" OR CommandLine: "*.inf,*" OR CommandLine: "*.inf\"*" OR CommandLine: "*.inf'*")) OR ((CommandLine="*.cpl" OR CommandLine="*.dll" OR CommandLine="*.inf"))) OR (CommandLine: "* -localserver *") OR (NOT CommandLine=*) OR (ParentImage="*\\msiexec.exe" AND (CommandLine: "*:\\Windows\\Installer\\*" AND CommandLine: "*.tmp*" AND CommandLine: "*zzzzInvokeManagedCustomActionOutOfProc*")))) AND NOT (((ParentCommandLine: "*:\\Users\\*" AND ParentCommandLine: "*\\AppData\\Local\\Microsoft\\EdgeUpdate\\Install\\{*" AND ParentCommandLine: "*\\EDGEMITMP_*" AND ParentCommandLine: "*.tmp\\setup.exe*" AND ParentCommandLine: "*--install-archive=*" AND ParentCommandLine: "*--previous-version=*" AND ParentCommandLine: "*--msedgewebview --verbose-logging --do-not-launch-msedge --user-level*"))))
