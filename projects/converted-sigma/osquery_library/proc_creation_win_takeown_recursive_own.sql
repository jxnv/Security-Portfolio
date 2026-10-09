-- Title: Suspicious Recursive Takeown
-- ID: 554601fb-9b71-4bcc-abf4-21a611be4fde
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-01-30
-- Tags: attack.defense-impairment, attack.t1222.001
-- Description: Adversaries can interact with the DACLs using built-in Windows commands takeown which can grant adversaries higher permissions on specific files and folders
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image="*\\takeown.exe" AND (CommandLine LIKE '%/f %' AND CommandLine LIKE '%/r%'))
