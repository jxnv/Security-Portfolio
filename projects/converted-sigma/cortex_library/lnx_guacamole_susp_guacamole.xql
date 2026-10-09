// Title: Guacamole Two Users Sharing Session Anomaly
// ID: 1edd77db-0669-4fef-9598-165bda82826d
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2020-07-03
// Tags: attack.credential-access, attack.t1212
// Description: Detects suspicious session with two users present
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ("(2 users now present)")
