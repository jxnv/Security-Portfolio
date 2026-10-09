// Title: Scheduled Task Creation Masquerading as System Processes
// ID: 9f8573c9-22b4-40e3-89c1-72bc2b8d49ab
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-02-05
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.stealth, attack.t1053.005, attack.t1036.004, attack.t1036.005
// Description: Detects the creation of scheduled tasks that involve system processes, which may indicate malicious actors masquerading as or abusing these processes to execute payloads or maintain persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "* /create *" AND (CommandLine: "* audiodg*" OR CommandLine: "* conhost*" OR CommandLine: "* dwm.exe*" OR CommandLine: "* explorer*" OR CommandLine: "* lsass*" OR CommandLine: "* lsm*" OR CommandLine: "* mmc*" OR CommandLine: "* msiexec*" OR CommandLine: "* regsvr32*" OR CommandLine: "* rundll32*" OR CommandLine: "* services*" OR CommandLine: "* spoolsv*" OR CommandLine: "* svchost*" OR CommandLine: "* taskeng*" OR CommandLine: "* taskhost*" OR CommandLine: "* wininit*" OR CommandLine: "* winlogon*")) AND ((Image="*\\schtasks.exe") OR (OriginalFileName: "schtasks.exe")))
