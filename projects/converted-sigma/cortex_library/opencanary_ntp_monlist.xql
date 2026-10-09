// Title: OpenCanary - NTP Monlist Request
// ID: 7cded4b3-f09e-405a-b96f-24248433ba44
// Status: test
// Level: high
// Author: Security Onion Solutions
// Date: 2024-03-08
// Tags: attack.impact, attack.t1498
// Description: Detects instances where an NTP service on an OpenCanary node has had a NTP monlist request.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (logtype = 11001)
