-- Title: DirectorySearcher Powershell Exploitation
-- ID: 1f6399cf-2c80-4924-ace1-6fcff3393480
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-02-12
-- Tags: attack.discovery, attack.t1018
-- Description: Enumerates Active Directory to determine computers that are joined to the domain
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ScriptBlockText ILIKE '%New-Object %' AND ScriptBlockText ILIKE '%System.DirectoryServices.DirectorySearcher%' AND ScriptBlockText ILIKE '%.PropertiesToLoad.Add%' AND ScriptBlockText ILIKE '%.findall()%' AND ScriptBlockText ILIKE '%Properties.name%'))
