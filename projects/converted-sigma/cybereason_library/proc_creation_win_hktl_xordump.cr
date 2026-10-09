// Title: HackTool - XORDump Execution
// ID: 66e563f9-1cbd-4a22-a957-d8b7c0f44372
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-28
// Tags: attack.stealth, attack.t1036, attack.t1003.001, attack.credential-access
// Description: Detects suspicious use of XORDump process memory dumping utility
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\xordump.exe") OR ((CommandLine contains " -process lsass.exe " OR CommandLine contains " -m comsvcs " OR CommandLine contains " -m dbghelp " OR CommandLine contains " -m dbgcore ")))
