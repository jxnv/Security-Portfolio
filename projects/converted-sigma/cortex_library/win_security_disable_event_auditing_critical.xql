// Title: Important Windows Event Auditing Disabled
// ID: ab4561b1-6c7e-48a7-ad08-087cfb9ce8f1
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-20
// Tags: attack.defense-impairment, attack.t1685.001
// Description: Detects scenarios where system auditing for important events such as "Process Creation" or "Logon" events is disabled.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4719 and (SubcategoryGuid = "{0CCE9210-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE9211-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE9212-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE9215-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE921B-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE922B-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE922F-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE9230-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE9235-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE9236-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE9237-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE923F-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE9240-69AE-11D9-BED3-505054503030}" or SubcategoryGuid = "{0CCE9242-69AE-11D9-BED3-505054503030}") and (AuditPolicyChanges contains "%%8448" or AuditPolicyChanges contains "%%8450")) or (EventID = 4719 and SubcategoryGuid = "{0CCE9217-69AE-11D9-BED3-505054503030}" and AuditPolicyChanges contains "%%8448"))
