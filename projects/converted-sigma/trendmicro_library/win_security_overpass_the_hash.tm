// Title: Successful Overpass the Hash Attempt
// ID: 192a0330-c20b-4356-90b6-7b7049ae0b87
// Status: test
// Level: high
// Author: Roberto Rodriguez (source), Dominik Schaudel (rule)
// Date: 2018-02-12
// Tags: attack.lateral-movement, attack.s0002, attack.t1550.002
// Description: Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.
// Converted by: Sigma Universal SIEM/EDR CLI

(EventID: "4624" AND LogonType: "9" AND LogonProcessName: "seclogo" AND AuthenticationPackageName: "Negotiate")
