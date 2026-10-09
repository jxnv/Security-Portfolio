// Title: Suspicious Get Local Groups Information - PowerShell
// ID: fa6a5a45-3ee2-4529-aa14-ee5edc9e29cb
// Status: test
// Level: low
// Author: frack113
// Date: 2021-12-12
// Tags: attack.discovery, attack.t1069.001
// Description: Detects the use of PowerShell modules and cmdlets to gather local group information.
// Adversaries may use local system permission groups to determine which groups exist and which users belong to a particular group such as the local administrators group.
// Converted by: Sigma Universal SIEM/EDR CLI

(((ScriptBlockText: "*get-localgroup *" OR ScriptBlockText: "*get-localgroupmember *")) OR ((ScriptBlockText: "*win32_group*") AND ((ScriptBlockText: "*get-wmiobject *" OR ScriptBlockText: "*gwmi *" OR ScriptBlockText: "*get-ciminstance *" OR ScriptBlockText: "*gcim *"))))
