// Title: Imports Registry Key From an ADS
// ID: 0b80ade5-6997-4b1d-99a1-71701778ea61
// Status: test
// Level: high
// Author: Oddvar Moe, Sander Wiebing, oscd.community
// Date: 2020-10-12
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects the import of a alternate datastream to the registry with regedit.exe.
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine: "* /i *" OR CommandLine: "*.reg*") AND CommandLine=regex(":[^ \\\\]")) AND ((Image="*\\regedit.exe") OR (OriginalFileName: "REGEDIT.EXE"))) AND NOT (((CommandLine: "* -e *" OR CommandLine: "* -a *" OR CommandLine: "* -c *"))))
