-- Title: Potentially Suspicious WebDAV LNK Execution
-- ID: 1412aa78-a24c-4abd-83df-767dfb2c5bbe
-- Status: test
-- Level: medium
-- Author: Micah Babinski
-- Date: 2023-08-21
-- Tags: attack.execution, attack.t1059.001, attack.t1204
-- Description: Detects possible execution via LNK file accessed on a WebDAV server.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ParentImage ILIKE '%\\explorer.exe' AND (Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\wscript.exe') AND CommandLine ILIKE '%\\DavWWWRoot\\%')
