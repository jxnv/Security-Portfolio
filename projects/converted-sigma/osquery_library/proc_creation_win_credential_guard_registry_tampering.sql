-- Title: Windows Credential Guard Registry Tampering Via CommandLine
-- ID: c17d47b7-dcd6-4109-87eb-d1817bd4cbc9
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-12-26
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects attempts to add, modify, or delete Windows Credential Guard related registry keys or values via command line tools such as Reg.exe or PowerShell.
-- Credential Guard uses virtualization-based security to isolate secrets so that only privileged system software can access them.
-- Adversaries may disable Credential Guard to gain access to sensitive credentials stored in the system, such as NTLM hashes and Kerberos tickets, which can be used for lateral movement and privilege escalation.
-- The rule matches suspicious command lines that target DeviceGuard or LSA registry paths and manipulate keys like EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures, or LsaCfgFlags.
-- Such activity may indicate an attempt to disable or tamper with Credential Guard, potentially exposing sensitive credentials for misuse.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%add %' OR CommandLine LIKE '%New-ItemProperty %' OR CommandLine LIKE '%Set-ItemProperty %' OR CommandLine LIKE '%si %' OR CommandLine LIKE '%delete %' OR CommandLine LIKE '%del %' OR CommandLine LIKE '%Remove-ItemProperty %' OR CommandLine LIKE '%rp %')) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\reg.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'reg.exe'))) AND ((CommandLine LIKE '%\\Control\\DeviceGuard%' OR CommandLine LIKE '%\\Control\\LSA%' OR CommandLine LIKE '%Software\\Policies\\Microsoft\\Windows\\DeviceGuard%')) AND ((CommandLine LIKE '%EnableVirtualizationBasedSecurity%' OR CommandLine LIKE '%RequirePlatformSecurityFeatures%' OR CommandLine LIKE '%LsaCfgFlags%')))
