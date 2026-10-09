// Title: Suspicious WMIC Execution Via Office Process
// ID: e1693bc8-7168-4eab-8718-cdcaa68a1738
// Status: test
// Level: high
// Author: Vadim Khrykov, Cyb3rEng
// Date: 2021-08-23
// Tags: attack.stealth, attack.t1204.002, attack.t1047, attack.t1218.010, attack.execution
// Description: Office application called wmic to proxye execution through a LOLBIN process. This is often used to break suspicious parent-child chain (Office app spawns LOLBin).
// Converted by: Sigma Universal SIEM/EDR CLI

(((ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\POWERPNT.exe" OR ParentImage="*\\MSPUB.exe" OR ParentImage="*\\VISIO.exe" OR ParentImage="*\\MSACCESS.EXE" OR ParentImage="*\\EQNEDT32.EXE" OR ParentImage="*\\ONENOTE.EXE" OR ParentImage="*\\wordpad.exe" OR ParentImage="*\\wordview.exe")) AND ((CommandLine contains "process" AND CommandLine contains "create" AND CommandLine contains "call") AND (CommandLine contains "regsvr32" OR CommandLine contains "rundll32" OR CommandLine contains "msiexec" OR CommandLine contains "mshta" OR CommandLine contains "verclsid" OR CommandLine contains "wscript" OR CommandLine contains "cscript")) AND ((Image="*\\wbem\\WMIC.exe") OR (OriginalFileName == "wmic.exe")))
