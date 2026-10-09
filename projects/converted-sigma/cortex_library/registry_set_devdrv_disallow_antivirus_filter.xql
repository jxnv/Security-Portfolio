// Title: Antivirus Filter Driver Disallowed On Dev Drive - Registry
// ID: 31e124fb-5dc4-42a0-83b3-44a69c77b271
// Status: test
// Level: high
// Author: @kostastsale, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-11-05
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects activity that indicates a user disabling the ability for Antivirus mini filter to inspect a "Dev Drive".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetObject endswith "\\FilterManager\\FltmgrDevDriveAllowAntivirusFilter" and Details = "DWORD (0x00000000)")
