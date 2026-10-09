// Title: Ntdsutil Abuse
// ID: e6e88853-5f20-4c4a-8d26-cd469fd8d31f
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-14
// Tags: attack.credential-access, attack.t1003.003
// Description: Detects potential abuse of ntdsutil to dump ntds.dit database
// Converted by: Sigma Universal SIEM/EDR CLI

(Provider_Name: "ESENT" AND (EventID: "216" OR EventID: "325" OR EventID: "326" OR EventID: "327") AND Data: "*ntds.dit*")
