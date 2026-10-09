// Title: RottenPotato Like Attack Pattern
// ID: 16f5d8ca-44bd-47c8-acbe-6fc95a16c12f
// Status: test
// Level: high
// Author: @SBousseaden, Florian Roth
// Date: 2019-11-15
// Tags: attack.collection, attack.privilege-escalation, attack.credential-access, attack.t1557.001
// Description: Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 4624 and LogonType = 3 and TargetUserName = "ANONYMOUS LOGON" and WorkstationName = "-" and (IpAddress = "127.0.0.1" or IpAddress = "::1"))
