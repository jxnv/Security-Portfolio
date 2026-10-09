// Title: Renamed CreateDump Utility Execution
// ID: 1a1ed54a-2ba4-4221-94d5-01dee560d71e
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-09-20
// Tags: attack.stealth, attack.t1036, attack.t1003.001, attack.credential-access
// Description: Detects uses of a renamed legitimate createdump.exe LOLOBIN utility to dump process memory
// Converted by: Sigma Universal SIEM/EDR CLI

(((((CommandLine: "* -u *" AND CommandLine: "* -f *" AND CommandLine: "*.dmp*")) OR ((CommandLine: "* --full *" AND CommandLine: "* --name *" AND CommandLine: "*.dmp*"))) OR (OriginalFileName: "FX_VER_INTERNALNAME_STR")) AND NOT ((Image="*\\createdump.exe")))
