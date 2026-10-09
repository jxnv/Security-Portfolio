// Title: Raccine Uninstall
// ID: a31eeaed-3fd5-478e-a8ba-e62c6b3f9ecc
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-01-21
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*taskkill *" AND CommandLine: "*RaccineSettings.exe*")) OR ((CommandLine: "*reg.exe*" AND CommandLine: "*delete*" AND CommandLine: "*Raccine Tray*")) OR ((CommandLine: "*schtasks*" AND CommandLine: "*/DELETE*" AND CommandLine: "*Raccine Rules Updater*")))
