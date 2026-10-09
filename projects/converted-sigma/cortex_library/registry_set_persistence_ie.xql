// Title: Modification of IE Registry Settings
// ID: d88d0ab2-e696-4d40-a2ed-9790064e66b3
// Status: test
// Level: low
// Author: frack113
// Date: 2022-01-22
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects modification of the registry settings used for Internet Explorer and other Windows components that use these settings. An attacker can abuse this registry key to add a domain to the trusted sites Zone or insert JavaScript for persistence
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings") and not (((Details = "Binary Data") or (Details startswith "DWORD") or (Details = null) or ((Details = "Cookie:" or Details = "Visited:" or Details = "(Empty)")) or ((TargetObject contains "\\Cache" or TargetObject contains "\\ZoneMap" or TargetObject contains "\\WpadDecision")))) and not ((TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Accepted Documents")))
