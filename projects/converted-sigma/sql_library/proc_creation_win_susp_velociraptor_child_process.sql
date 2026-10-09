-- Title: Suspicious Velociraptor Child Process
-- ID: 4bc90587-e6ca-4b41-be0b-ed4d04e4ed0c
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-08-29
-- Tags: attack.command-and-control, attack.persistence, attack.t1219
-- Description: Detects the suspicious use of the Velociraptor DFIR tool to execute other tools or download additional payloads, as seen in a campaign where it was abused for remote access and to stage further attacks.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ParentImage ILIKE '%\\Velociraptor.exe') AND (((CommandLine ILIKE '%msiexec%' AND CommandLine ILIKE '%/i%' AND CommandLine ILIKE '%http%')) OR ((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\powershell_ise.exe' OR Image ILIKE '%\\pwsh.exe') AND (CommandLine ILIKE '%Invoke-WebRequest %' OR CommandLine ILIKE '%IWR %' OR CommandLine ILIKE '%.DownloadFile%' OR CommandLine ILIKE '%.DownloadString%')) OR ((CommandLine ILIKE '%code.exe%' AND CommandLine ILIKE '%tunnel%' AND CommandLine ILIKE '%--accept-server-license-terms%'))))
