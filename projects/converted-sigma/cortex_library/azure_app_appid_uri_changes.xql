// Title: Application AppID Uri Configuration Changes
// ID: 1b45b0d1-773f-4f23-aedc-814b759563b1
// Status: test
// Level: high
// Author: Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
// Date: 2022-06-02
// Tags: attack.initial-access, attack.persistence, attack.credential-access, attack.privilege-escalation, attack.stealth, attack.t1552, attack.t1078.004
// Description: Detects when a configuration change is made to an applications AppID URI.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((properties.message = "Update Application" or properties.message = "Update Service principal"))
