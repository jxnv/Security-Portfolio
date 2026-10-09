// Title: UAC Bypass Abusing Winsat Path Parsing - Registry
// ID: 6597be7b-ac61-4ac8-bef4-d3ec88174853
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-08-30
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)
// Converted by: Sigma Universal SIEM/EDR CLI

(TargetObject: "*\\Root\\InventoryApplicationFile\\winsat.exe|*" AND TargetObject="*\\LowerCaseLongPath" AND Details="c:\\users\\*" AND Details="*\\appdata\\local\\temp\\system32\\winsat.exe")
