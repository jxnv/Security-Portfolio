// Title: Suspicious SYSVOL Domain Group Policy Access
// ID: 05f3c945-dcc8-4393-9f3d-af65077a8f86
// Status: test
// Level: medium
// Author: Markus Neis, Jonhnathan Ribeiro, oscd.community
// Date: 2018-04-09
// Tags: attack.credential-access, attack.t1552.006
// Description: Detects Access to Domain Group Policies stored in SYSVOL
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains "\\SYSVOL\\" AND CommandLine contains "\\policies\\"))
