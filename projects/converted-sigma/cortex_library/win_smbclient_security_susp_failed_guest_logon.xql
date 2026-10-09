// Title: Suspicious Rejected SMB Guest Logon From IP
// ID: 71886b70-d7b4-4dbf-acce-87d2ca135262
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), KevTheHermit, fuzzyf10w
// Date: 2021-06-30
// Tags: attack.credential-access, attack.t1110.001
// Description: Detect Attempt PrintNightmare (CVE-2021-1675) Remote code execution in Windows Spooler Service
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 31017 and UserName = "" and ServerName startswith "\\1")
