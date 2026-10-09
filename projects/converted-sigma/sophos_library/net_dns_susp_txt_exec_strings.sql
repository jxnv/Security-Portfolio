-- Title: DNS TXT Answer with Possible Execution Strings
-- ID: 8ae51330-899c-4641-8125-e39f2e07da72
-- Status: test
-- Level: high
-- Author: Markus Neis
-- Date: 2018-08-08
-- Tags: attack.command-and-control, attack.t1071.004
-- Description: Detects strings used in command execution in DNS TXT Answer
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (record_type = 'TXT' AND (answer ILIKE '%IEX%' OR answer ILIKE '%Invoke-Expression%' OR answer ILIKE '%cmd.exe%'))
