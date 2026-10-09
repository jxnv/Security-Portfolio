// Title: Admin User Remote Logon
// ID: 0f63e1ef-1eb9-4226-9d54-8927ca08520a
// Status: test
// Level: low
// Author: juju4
// Date: 2017-10-29
// Tags: attack.privilege-escalation, attack.persistence, attack.lateral-movement, attack.initial-access, attack.stealth, attack.t1078.001, attack.t1078.002, attack.t1078.003, car.2016-04-005
// Description: Detect remote login by Administrator user (depending on internal pattern).
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 4624 and LogonType = 10 and AuthenticationPackageName = "Negotiate" and TargetUserName startswith "Admin")
