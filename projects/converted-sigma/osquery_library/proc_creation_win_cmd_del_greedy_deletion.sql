-- Title: Greedy File Deletion Using Del
-- ID: 204b17ae-4007-471b-917b-b917b315c5db
-- Status: test
-- Level: medium
-- Author: frack113 , X__Junior (Nextron Systems)
-- Date: 2021-12-02
-- Tags: attack.stealth, attack.t1070.004
-- Description: Detects execution of the "del" builtin command to remove files using greedy/wildcard expression. This is often used by malware to delete content of folders that perhaps contains the initial malware infection or to delete evidence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%del %' OR CommandLine LIKE '%erase %')) AND ((CommandLine LIKE '%\\\\\\*.au3%' OR CommandLine LIKE '%\\\\\\*.dll%' OR CommandLine LIKE '%\\\\\\*.exe%' OR CommandLine LIKE '%\\\\\\*.js%')) AND ((Image="*\\cmd.exe") OR (OriginalFileName = 'Cmd.Exe')))
