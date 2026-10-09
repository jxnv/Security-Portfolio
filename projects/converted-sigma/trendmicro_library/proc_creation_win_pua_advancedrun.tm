// Title: PUA - AdvancedRun Execution
// ID: d2b749ee-4225-417e-b20e-a8d2193cbb84
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-20
// Tags: attack.execution, attack.privilege-escalation, attack.stealth, attack.t1564.003, attack.t1134.002, attack.t1059.003
// Description: Detects the execution of AdvancedRun utility
// Converted by: Sigma Universal SIEM/EDR CLI

((OriginalFileName: "AdvancedRun.exe") OR ((CommandLine: "* /EXEFilename *" AND CommandLine: "* /Run*")) OR ((CommandLine: "* /WindowState 0*" AND CommandLine: "* /RunAs *" AND CommandLine: "* /CommandLine *")))
