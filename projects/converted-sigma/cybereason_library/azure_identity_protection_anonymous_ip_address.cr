// Title: Anonymous IP Address
// ID: 53acd925-2003-440d-a1f3-71a5253fe237
// Status: test
// Level: high
// Author: Gloria Lee, '@gleeiamglo'
// Date: 2023-08-22
// Tags: attack.t1528, attack.credential-access
// Description: Indicates sign-ins from an anonymous IP address, for example, using an anonymous browser or VPN.
// Converted by: Sigma Universal SIEM/EDR CLI

(riskEventType == "anonymizedIPAddress")
