-- Title: DumpStack.log Defender Evasion
-- ID: 4f647cfa-b598-4e12-ad69-c68dd16caef8
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-01-06
-- Tags: attack.defense-impairment
-- Description: Detects the use of the filename DumpStack.log to evade Microsoft Defender
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\DumpStack.log") OR (CommandLine LIKE '% -o DumpStack.log%'))
