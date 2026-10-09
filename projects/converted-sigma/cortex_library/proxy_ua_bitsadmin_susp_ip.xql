// Title: Bitsadmin to Uncommon IP Server Address
// ID: 8ccd35a2-1c7c-468b-b568-ac6cdf80eec3
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-06-10
// Tags: attack.command-and-control, attack.execution, attack.stealth, attack.t1071.001, attack.persistence, attack.t1197, attack.s0190
// Description: Detects Bitsadmin connections to IP addresses instead of FQDN names
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (c-useragent startswith "Microsoft BITS/" and (cs-host endswith "1" or cs-host endswith "2" or cs-host endswith "3" or cs-host endswith "4" or cs-host endswith "5" or cs-host endswith "6" or cs-host endswith "7" or cs-host endswith "8" or cs-host endswith "9"))
