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

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\reg.exe' AND (CommandLine ILIKE '% query %' AND CommandLine ILIKE '%/t %' AND CommandLine ILIKE '%REG_SZ%' AND CommandLine ILIKE '%/s%')) AND (((CommandLine ILIKE '%/f %' AND CommandLine ILIKE '%HKLM%')) OR ((CommandLine ILIKE '%/f %' AND CommandLine ILIKE '%HKCU%')) OR (CommandLine ILIKE '%HKCU\\Software\\SimonTatham\\PuTTY\\Sessions%')))
