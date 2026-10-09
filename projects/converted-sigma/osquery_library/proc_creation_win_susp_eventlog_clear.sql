-- Title: Suspicious Eventlog Clearing or Configuration Change Activity
-- ID: cc36992a-4671-4f21-a91d-6c2b72a2edf5
-- Status: stable
-- Level: high
-- Author: Ecco, Daniil Yugoslavskiy, oscd.community, D3F7A5105, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2019-09-26
-- Tags: attack.defense-impairment, attack.t1685.005, attack.t1685.001, car.2016-04-002
-- Description: Detects the clearing or configuration tampering of EventLog using utilities such as "wevtutil", "powershell" and "wmic".
-- This technique were seen used by threat actors and ransomware strains in order to evade defenses.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((((CommandLine LIKE '%clear-log %' OR CommandLine LIKE '% cl %' OR CommandLine LIKE '%set-log %' OR CommandLine LIKE '% sl %' OR CommandLine LIKE '%lfn:%')) AND ((Image="*\\wevtutil.exe") OR (OriginalFileName = 'wevtutil.exe'))) OR ((((CommandLine LIKE '%Clear-EventLog %' OR CommandLine LIKE '%Remove-EventLog %' OR CommandLine LIKE '%Limit-EventLog %' OR CommandLine LIKE '%Clear-WinEvent %')) OR ((CommandLine LIKE '%Eventing.Reader.EventLogSession%' AND CommandLine LIKE '%ClearLog%')) OR ((CommandLine LIKE '%Diagnostics.EventLog%' AND CommandLine LIKE '%Clear%'))) AND ((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe"))) OR ((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe" OR Image="*\\wmic.exe") AND CommandLine LIKE '%ClearEventLog%')) AND NOT (((ParentImage = 'C:\\Windows\\SysWOW64\\msiexec.exe' OR ParentImage = 'C:\\Windows\\System32\\msiexec.exe') AND CommandLine LIKE '% sl %')))
