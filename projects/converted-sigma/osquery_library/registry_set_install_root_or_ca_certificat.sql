-- Title: New Root or CA or AuthRoot Certificate to Store
-- ID: d223b46b-5621-4037-88fe-fda32eead684
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-04-04
-- Tags: attack.impact, attack.t1490
-- Description: Detects the addition of new root, CA or AuthRoot certificates to the Windows registry
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates\\%' OR TargetObject LIKE '%\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\%' OR TargetObject LIKE '%\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\%' OR TargetObject LIKE '%\\SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates\\%' OR TargetObject LIKE '%\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\CA\\Certificates\\%' OR TargetObject LIKE '%\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\CA\\Certificates\\%' OR TargetObject LIKE '%\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\%' OR TargetObject LIKE '%\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\%' OR TargetObject LIKE '%\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\AuthRoot\\Certificates\\%') AND TargetObject="*\\Blob" AND Details = 'Binary Data')
