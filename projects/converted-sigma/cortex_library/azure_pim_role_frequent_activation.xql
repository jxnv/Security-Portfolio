// Title: Roles Activated Too Frequently
// ID: 645fd80d-6c07-435b-9e06-7bc1b5656cba
// Status: test
// Level: high
// Author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
// Date: 2023-09-14
// Tags: attack.initial-access, attack.stealth, attack.t1078, attack.persistence, attack.privilege-escalation
// Description: Identifies when the same privilege role has multiple activations by the same user.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (riskEventType = "sequentialActivationRenewalsAlertIncident")
