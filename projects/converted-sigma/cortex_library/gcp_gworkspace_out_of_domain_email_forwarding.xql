// Title: Google Workspace Out Of Domain Email Forwarding
// ID: 2a0bb2dd-eb5f-4517-8cb9-404f8ba764a5
// Status: experimental
// Level: medium
// Author: Tom kluter
// Date: 2026-04-28
// Tags: attack.t1114.003, attack.collection
// Description: Detects automatic email forwarding to external domains in Google Workspace, which may indicate data leakage or misuse.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (protoPayload.serviceName = "login.googleapis.com" and protoPayload.metadata.event.eventName = "email_forwarding_out_of_domain")
