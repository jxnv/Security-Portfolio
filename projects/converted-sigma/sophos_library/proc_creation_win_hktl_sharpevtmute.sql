-- Title: HackTool - SharpEvtMute Execution
-- ID: bedfc8ad-d1c7-4e37-a20e-e2b0dbee759c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-09-07
-- Tags: attack.defense-impairment, attack.t1685.001
-- Description: Detects the use of SharpEvtHook, a tool that tampers with the Windows event logs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\SharpEvtMute.exe') OR (Description = 'SharpEvtMute') OR ((CommandLine ILIKE '%--Filter \"rule %' OR CommandLine ILIKE '%--Encoded --Filter \\\"%')))
