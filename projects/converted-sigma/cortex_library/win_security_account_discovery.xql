// Title: AD Privileged Users or Groups Reconnaissance
// ID: 35ba1d85-724d-42a3-889f-2e2362bcaf23
// Status: test
// Level: high
// Author: Samir Bousseaden
// Date: 2019-04-03
// Tags: attack.discovery, attack.t1087.002
// Description: Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4661 and (ObjectType = "SAM_USER" or ObjectType = "SAM_GROUP")) and (((ObjectName endswith "-512" or ObjectName endswith "-502" or ObjectName endswith "-500" or ObjectName endswith "-505" or ObjectName endswith "-519" or ObjectName endswith "-520" or ObjectName endswith "-544" or ObjectName endswith "-551" or ObjectName endswith "-555")) or (ObjectName contains "admin")) and not ((SubjectUserName endswith "$")))
