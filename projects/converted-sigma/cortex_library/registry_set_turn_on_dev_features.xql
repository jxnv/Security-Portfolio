// Title: Potential Signing Bypass Via Windows Developer Features - Registry
// ID: b110ebaf-697f-4da1-afd5-b536fa27a2c1
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-12
// Tags: attack.stealth
// Description: Detects when the enablement of developer features such as "Developer Mode" or "Application Sideloading". Which allows the user to install untrusted packages.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock" or TargetObject contains "\\Policies\\Microsoft\\Windows\\Appx\\") and (TargetObject endswith "\\AllowAllTrustedApps" or TargetObject endswith "\\AllowDevelopmentWithoutDevLicense") and Details = "DWORD (0x00000001)")
