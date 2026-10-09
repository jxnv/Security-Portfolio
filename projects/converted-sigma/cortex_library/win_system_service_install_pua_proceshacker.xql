// Title: ProcessHacker Privilege Elevation
// ID: c4ff1eac-84ad-44dd-a6fb-d56a92fc43a9
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-05-27
// Tags: attack.persistence, attack.execution, attack.privilege-escalation, attack.t1543.003, attack.t1569.002
// Description: Detects a ProcessHacker tool that elevated privileges to a very high level
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (Provider_Name = "Service Control Manager" and EventID = 7045 and ServiceName startswith "ProcessHacker" and AccountName = "LocalSystem")
