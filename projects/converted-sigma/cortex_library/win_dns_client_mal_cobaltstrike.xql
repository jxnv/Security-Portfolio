// Title: Suspicious Cobalt Strike DNS Beaconing - DNS Client
// ID: 0d18728b-f5bf-4381-9dcf-915539fff6c2
// Status: test
// Level: critical
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-16
// Tags: attack.t1071.004, attack.command-and-control
// Description: Detects a program that invoked suspicious DNS queries known from Cobalt Strike beacons
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 3008) and (((QueryName startswith "aaa.stage." or QueryName startswith "post.1")) or (QueryName contains ".stage.123456.")))
