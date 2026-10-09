// Title: New Root or CA or AuthRoot Certificate to Store
// ID: d223b46b-5621-4037-88fe-fda32eead684
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-04-04
// Tags: attack.impact, attack.t1490
// Description: Detects the addition of new root, CA or AuthRoot certificates to the Windows registry
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates\\" or TargetObject contains "\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\" or TargetObject contains "\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\" or TargetObject contains "\\SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates\\" or TargetObject contains "\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\CA\\Certificates\\" or TargetObject contains "\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\CA\\Certificates\\" or TargetObject contains "\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\" or TargetObject contains "\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\" or TargetObject contains "\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\AuthRoot\\Certificates\\") and TargetObject endswith "\\Blob" and Details = "Binary Data")
