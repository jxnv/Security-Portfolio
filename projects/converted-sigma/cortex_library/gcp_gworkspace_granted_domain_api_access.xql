// Title: Google Workspace Granted Domain API Access
// ID: 04e2a23a-9b29-4a5c-be3a-3542e3f982ba
// Status: test
// Level: medium
// Author: Austin Songer
// Date: 2021-08-23
// Tags: attack.privilege-escalation, attack.persistence, attack.t1098
// Description: Detects when an API access service account is granted domain authority.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (eventService = "admin.googleapis.com" and eventName = "AUTHORIZE_API_CLIENT_ACCESS")
