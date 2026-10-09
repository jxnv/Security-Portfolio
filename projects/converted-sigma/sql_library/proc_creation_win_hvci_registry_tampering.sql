-- Title: Hypervisor-protected Code Integrity (HVCI) Related Registry Tampering Via CommandLine
-- ID: 6225c53a-a96e-4235-b28f-8d7997cd96eb
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-01-26
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects the tampering of Hypervisor-protected Code Integrity (HVCI) related registry values via command line tool reg.exe.
-- HVCI uses virtualization-based security to protect code integrity by ensuring that only trusted code can run in kernel mode.
-- Adversaries may tamper with HVCI to load malicious or unsigned drivers, which can be used to escalate privileges, maintain persistence, or evade security mechanisms.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%add %' OR CommandLine ILIKE '%New-ItemProperty %' OR CommandLine ILIKE '%Set-ItemProperty %' OR CommandLine ILIKE '%si %')) AND (CommandLine ILIKE '%\\DeviceGuard%') AND ((CommandLine ILIKE '%EnableVirtualizationBasedSecurity%' OR CommandLine ILIKE '%HypervisorEnforcedCodeIntegrity%')) AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\reg.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'reg.exe'))))
