// Title: New CA Policy by Non-approved Actor
// ID: 0922467f-db53-4348-b7bf-dee8d0d348c6
// Status: test
// Level: medium
// Author: Corissa Koopmans, '@corissalea'
// Date: 2022-07-18
// Tags: attack.privilege-escalation, attack.t1548
// Description: Monitor and alert on conditional access changes.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (properties.message = "Add conditional access policy")
