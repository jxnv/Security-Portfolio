// Title: Raccine Uninstall
// ID: a31eeaed-3fd5-478e-a8ba-e62c6b3f9ecc
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-01-21
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "taskkill " AND CommandLine contains "RaccineSettings.exe")) OR ((CommandLine contains "reg.exe" AND CommandLine contains "delete" AND CommandLine contains "Raccine Tray")) OR ((CommandLine contains "schtasks" AND CommandLine contains "/DELETE" AND CommandLine contains "Raccine Rules Updater")))
