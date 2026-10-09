-- Title: Enumeration for Credentials in Registry
-- ID: e0b0c2ab-3d52-46d9-8cb7-049dc775fbd1
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-20
-- Tags: attack.credential-access, attack.t1552.002
-- Description: Adversaries may search the Registry on compromised systems for insecurely stored credentials.
-- The Windows Registry stores configuration information that can be used by the system or other programs.
-- Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\reg.exe" AND (CommandLine LIKE '% query %' AND CommandLine LIKE '%/t %' AND CommandLine LIKE '%REG_SZ%' AND CommandLine LIKE '%/s%')) AND (((CommandLine LIKE '%/f %' AND CommandLine LIKE '%HKLM%')) OR ((CommandLine LIKE '%/f %' AND CommandLine LIKE '%HKCU%')) OR (CommandLine LIKE '%HKCU\\Software\\SimonTatham\\PuTTY\\Sessions%')))
