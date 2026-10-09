-- Title: RDP Enable or Disable via Win32_TerminalServiceSetting WMI Class
-- ID: 4b8f6d3a-9c5e-4f2a-a7d8-6b9c3e5f2a8d
-- Status: experimental
-- Level: medium
-- Author: Daniel Koifman (KoifSec), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-11-15
-- Tags: attack.lateral-movement, attack.t1021.001, attack.execution, attack.t1047
-- Description: Detects enabling or disabling of Remote Desktop Protocol (RDP) using alternate methods such as WMIC or PowerShell.
-- In PowerShell one-liner commands, the "SetAllowTSConnections" method of the "Win32_TerminalServiceSetting" class may be used to enable or disable RDP.
-- In WMIC, the "rdtoggle" alias or "Win32_TerminalServiceSetting" class may be used for the same purpose.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%rdtoggle%' OR CommandLine ILIKE '%Win32_TerminalServiceSetting%')) AND (CommandLine ILIKE '%SetAllowTSConnections%') AND (((Image ILIKE '%\\wmic.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'wmic.exe' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))
