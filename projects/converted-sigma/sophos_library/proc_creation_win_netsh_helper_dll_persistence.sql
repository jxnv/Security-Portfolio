-- Title: Potential Persistence Via Netsh Helper DLL
-- ID: 56321594-9087-49d9-bf10-524fe8479452
-- Status: test
-- Level: medium
-- Author: Victor Sergeev, oscd.community
-- Date: 2019-10-25
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1546.007, attack.s0108
-- Description: Detects the execution of netsh with "add helper" flag in order to add a custom helper DLL. This technique can be abused to add a malicious helper DLL that can be used as a persistence proxy that gets called when netsh.exe is executed.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%add%' AND CommandLine ILIKE '%helper%')) AND ((OriginalFileName = 'netsh.exe') OR (Image ILIKE '%\\netsh.exe')))
