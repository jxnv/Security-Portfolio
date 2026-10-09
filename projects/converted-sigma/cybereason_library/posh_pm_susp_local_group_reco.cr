// Title: Suspicious Get Local Groups Information
// ID: cef24b90-dddc-4ae1-a09a-8764872f69fc
// Status: test
// Level: low
// Author: frack113
// Date: 2021-12-12
// Tags: attack.discovery, attack.t1069.001
// Description: Detects the use of PowerShell modules and cmdlets to gather local group information.
// Adversaries may use local system permission groups to determine which groups exist and which users belong to a particular group such as the local administrators group.
// Converted by: Sigma Universal SIEM/EDR CLI

((((Payload contains "get-localgroup " OR Payload contains "get-localgroupmember ")) OR ((ContextInfo contains "get-localgroup " OR ContextInfo contains "get-localgroupmember "))) OR (((Payload contains "win32_group") OR (ContextInfo contains "win32_group")) AND (((Payload contains "get-wmiobject " OR Payload contains "gwmi " OR Payload contains "get-ciminstance " OR Payload contains "gcim ")) OR ((ContextInfo contains "get-wmiobject " AND ContextInfo contains "gwmi " AND ContextInfo contains "get-ciminstance " AND ContextInfo contains "gcim ")))))
