// Title: Windows Defender Exclusion Registry Key - Write Access Requested
// ID: e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d
// Status: test
// Level: medium
// Author: @BarryShooshooga, Nasreddine Bencherchali (Nextron Systems)
// Date: 2019-10-26
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects write access requests to the Windows Defender exclusions registry keys. This could be an indication of an attacker trying to request a handle or access the object to write new exclusions in order to bypass security.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((AccessList contains "%%4417" or AccessList contains "%%4418") and (EventID = 4656 or EventID = 4663) and ObjectName contains "\\Microsoft\\Windows Defender\\Exclusions\\")
