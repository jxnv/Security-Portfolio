-- Title: Suspicious Velociraptor Child Process
-- ID: 4bc90587-e6ca-4b41-be0b-ed4d04e4ed0c
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-08-29
-- Tags: attack.command-and-control, attack.persistence, attack.t1219
-- Description: Detects the suspicious use of the Velociraptor DFIR tool to execute other tools or download additional payloads, as seen in a campaign where it was abused for remote access and to stage further attacks.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((ParentImage="*\\Velociraptor.exe") AND (((CommandLine LIKE '%msiexec%' AND CommandLine LIKE '%/i%' AND CommandLine LIKE '%http%')) OR ((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe") AND (CommandLine LIKE '%Invoke-WebRequest %' OR CommandLine LIKE '%IWR %' OR CommandLine LIKE '%.DownloadFile%' OR CommandLine LIKE '%.DownloadString%')) OR ((CommandLine LIKE '%code.exe%' AND CommandLine LIKE '%tunnel%' AND CommandLine LIKE '%--accept-server-license-terms%'))))
