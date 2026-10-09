-- Title: HackTool - SharpEvtMute Execution
-- ID: bedfc8ad-d1c7-4e37-a20e-e2b0dbee759c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-09-07
-- Tags: attack.defense-impairment, attack.t1685.001
-- Description: Detects the use of SharpEvtHook, a tool that tampers with the Windows event logs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\SharpEvtMute.exe") OR (Description = 'SharpEvtMute') OR ((CommandLine LIKE '%--Filter \"rule %' OR CommandLine LIKE '%--Encoded --Filter \\\"%')))
