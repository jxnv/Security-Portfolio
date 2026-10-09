-- Title: Potential Signing Bypass Via Windows Developer Features - Registry
-- ID: b110ebaf-697f-4da1-afd5-b536fa27a2c1
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-12
-- Tags: attack.stealth
-- Description: Detects when the enablement of developer features such as "Developer Mode" or "Application Sideloading". Which allows the user to install untrusted packages.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock%' OR TargetObject LIKE '%\\Policies\\Microsoft\\Windows\\Appx\\%') AND (TargetObject="*\\AllowAllTrustedApps" OR TargetObject="*\\AllowDevelopmentWithoutDevLicense") AND Details = 'DWORD (0x00000001)')
