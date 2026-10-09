// Title: Google Cloud Service Account Modified
// ID: 6b67c12e-5e40-47c6-b3b0-1e6b571184cc
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-08-14
// Tags: attack.impact
// Description: Identifies when a service account is modified in Google Cloud.
// Converted by: Sigma Universal SIEM/EDR CLI

((gcp.audit.method_name="*.serviceAccounts.patch" OR gcp.audit.method_name="*.serviceAccounts.create" OR gcp.audit.method_name="*.serviceAccounts.update" OR gcp.audit.method_name="*.serviceAccounts.enable" OR gcp.audit.method_name="*.serviceAccounts.undelete"))
