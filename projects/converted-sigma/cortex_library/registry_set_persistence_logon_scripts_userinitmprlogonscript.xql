// Title: Potential Persistence Via Logon Scripts - Registry
// ID: 9ace0707-b560-49b8-b6ca-5148b42f39fb
// Status: test
// Level: medium
// Author: Tom Ueltschi (@c_APT_ure)
// Date: 2019-01-12
// Tags: attack.privilege-escalation, attack.t1037.001, attack.persistence, attack.lateral-movement
// Description: Detects creation of "UserInitMprLogonScript" registry value which can be used as a persistence method by malicious actors
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetObject contains "UserInitMprLogonScript")
