// Title: DHCP Server Error Failed Loading the CallOut DLL
// ID: 75edd3fd-7146-48e5-9848-3013d7f0282c
// Status: test
// Level: high
// Author: Dimitrios Slamaris, @atc_project (fix)
// Date: 2017-05-15
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
// Description: This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 1031 or EventID = 1032 or EventID = 1034) and Provider_Name = "Microsoft-Windows-DHCP-Server")
