// Title: Uncommon Userinit Child Process
// ID: 0a98a10c-685d-4ab0-bddc-b6bdd1d48458
// Status: test
// Level: high
// Author: Tom Ueltschi (@c_APT_ure), Tim Shelton
// Date: 2019-01-12
// Tags: attack.privilege-escalation, attack.t1037.001, attack.persistence
// Description: Detects uncommon "userinit.exe" child processes, which could be a sign of uncommon shells or login scripts used for persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\userinit.exe") AND NOT ((Image="*:\\WINDOWS\\explorer.exe")) AND NOT ((((Image="*:\\Program Files (x86)\\Citrix\\HDX\\bin\\cmstart.exe" OR Image="*:\\Program Files (x86)\\Citrix\\HDX\\bin\\icast.exe" OR Image="*:\\Program Files (x86)\\Citrix\\System32\\icast.exe" OR Image="*:\\Program Files\\Citrix\\HDX\\bin\\cmstart.exe" OR Image="*:\\Program Files\\Citrix\\HDX\\bin\\icast.exe" OR Image="*:\\Program Files\\Citrix\\System32\\icast.exe")) OR (NOT Image=*) OR ((CommandLine: "*netlogon.bat*" OR CommandLine: "*UsrLogon.cmd*")) OR ((Image="*:\\Windows\\System32\\proquota.exe" OR Image="*:\\Windows\\SysWOW64\\proquota.exe")) OR (CommandLine: "PowerShell.exe"))))
