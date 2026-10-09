// Title: Password Policy Enumerated
// ID: 12ba6a38-adb3-4d6b-91ba-a7fb248e3199
// Status: test
// Level: medium
// Author: Zach Mathis
// Date: 2023-05-19
// Tags: attack.discovery, attack.t1201
// Description: Detects when the password policy is enumerated.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 4661 and AccessList contains "%%5392" and ObjectServer = "Security Account Manager")
