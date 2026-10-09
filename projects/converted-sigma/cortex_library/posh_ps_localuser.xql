// Title: Powershell LocalAccount Manipulation
// ID: 4fdc44df-bfe9-4fcc-b041-68f5a2d3031c
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-12-28
// Tags: attack.privilege-escalation, attack.persistence, attack.t1098
// Description: Adversaries may manipulate accounts to maintain access to victim systems.
// Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "Disable-LocalUser" or ScriptBlockText contains "Enable-LocalUser" or ScriptBlockText contains "Get-LocalUser" or ScriptBlockText contains "Set-LocalUser" or ScriptBlockText contains "New-LocalUser" or ScriptBlockText contains "Rename-LocalUser" or ScriptBlockText contains "Remove-LocalUser"))
