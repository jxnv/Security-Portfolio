// Title: OneLogin User Account Locked
// ID: a717c561-d117-437e-b2d9-0118a7035d01
// Status: test
// Level: low
// Author: Austin Songer @austinsonger
// Date: 2021-10-12
// Tags: attack.impact
// Description: Detects when an user account is locked or suspended.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((event_type_id = 532) or (event_type_id = 553) or (event_type_id = 551))
