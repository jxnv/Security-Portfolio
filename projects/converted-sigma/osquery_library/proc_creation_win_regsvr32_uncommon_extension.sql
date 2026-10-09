-- Title: Regsvr32 DLL Execution With Uncommon Extension
-- ID: 50919691-7302-437f-8e10-1fe088afa145
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-07-17
-- Tags: attack.privilege-escalation, attack.persistence, attack.stealth, attack.t1574, attack.execution
-- Description: Detects a "regsvr32" execution where the DLL doesn't contain a common file extension.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\regsvr32.exe") OR (OriginalFileName = 'REGSVR32.EXE')) AND NOT (((CommandLine = '') OR ((CommandLine LIKE '%.ax%' OR CommandLine LIKE '%.cpl%' OR CommandLine LIKE '%.dll%' OR CommandLine LIKE '%.ocx%')) OR (NOT CommandLine=*))) AND NOT (((CommandLine LIKE '%.bav%') OR (CommandLine LIKE '%.ppl%'))))
