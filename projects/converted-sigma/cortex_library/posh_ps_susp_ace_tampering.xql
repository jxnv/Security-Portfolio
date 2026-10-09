// Title: Potential Persistence Via Security Descriptors - ScriptBlock
// ID: 2f77047c-e6e9-4c11-b088-a3de399524cd
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-05
// Tags: attack.persistence, attack.privilege-escalation, attack.defense-impairment
// Description: Detects usage of certain functions and keywords that are used to manipulate security descriptors in order to potentially set a backdoor. As seen used in the DAMP project.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "win32_Trustee" and ScriptBlockText contains "win32_Ace" and ScriptBlockText contains ".AccessMask" and ScriptBlockText contains ".AceType" and ScriptBlockText contains ".SetSecurityDescriptor") and (ScriptBlockText contains "\\Lsa\\JD" or ScriptBlockText contains "\\Lsa\\Skew1" or ScriptBlockText contains "\\Lsa\\Data" or ScriptBlockText contains "\\Lsa\\GBG"))
