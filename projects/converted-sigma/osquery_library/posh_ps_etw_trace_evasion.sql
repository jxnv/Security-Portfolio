-- Title: Disable of ETW Trace - Powershell
-- ID: 115fdba9-f017-42e6-84cf-d5573bf2ddf8
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-28
-- Tags: attack.stealth, attack.defense-impairment, attack.t1070, attack.t1685, car.2016-04-002
-- Description: Detects usage of powershell cmdlets to disable or remove ETW trace sessions
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%Remove-EtwTraceProvider %') OR ((ScriptBlockText LIKE '%Set-EtwTraceProvider %' AND ScriptBlockText LIKE '%0x11%')))
