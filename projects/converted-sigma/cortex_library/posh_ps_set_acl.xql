// Title: PowerShell Script Change Permission Via Set-Acl - PsScript
// ID: cae80281-ef23-44c5-873b-fd48d2666f49
// Status: test
// Level: low
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-07-18
// Tags: attack.defense-impairment, attack.t1222
// Description: Detects PowerShell scripts set ACL to of a file or a folder
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "Set-Acl " and ScriptBlockText contains "-AclObject " and ScriptBlockText contains "-Path "))
