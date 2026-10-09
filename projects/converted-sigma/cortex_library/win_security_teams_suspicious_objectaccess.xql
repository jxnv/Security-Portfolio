// Title: Suspicious Teams Application Related ObjectAcess Event
// ID: 25cde13e-8e20-4c29-b949-4e795b76f16f
// Status: test
// Level: high
// Author: @SerkinValery
// Date: 2022-09-16
// Tags: attack.credential-access, attack.t1528
// Description: Detects an access to authentication tokens and accounts of Microsoft Teams desktop application.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4663 and (ObjectName contains "\\Microsoft\\Teams\\Cookies" or ObjectName contains "\\Microsoft\\Teams\\Local Storage\\leveldb")) and not ((ProcessName contains "\\Microsoft\\Teams\\current\\Teams.exe")))
