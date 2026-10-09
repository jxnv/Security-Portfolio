// Title: HybridConnectionManager Service Running
// ID: b55d23e5-6821-44ff-8a6e-67218891e49f
// Status: test
// Level: high
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2021-04-12
// Tags: attack.persistence, attack.t1554
// Description: Rule to detect the Hybrid Connection Manager service running on an endpoint.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((EventID = 40300 or EventID = 40301 or EventID = 40302)) and ("HybridConnection" or "sb://" or "servicebus.windows.net" or "HybridConnectionManage"))
