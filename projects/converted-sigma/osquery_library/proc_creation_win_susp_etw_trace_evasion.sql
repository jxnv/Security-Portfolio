-- Title: ETW Trace Evasion Activity
-- ID: a238b5d0-ce2d-4414-a676-7a531b3d13d6
-- Status: test
-- Level: high
-- Author: @neu5ron, Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
-- Date: 2019-03-22
-- Tags: attack.stealth, attack.defense-impairment, attack.t1070, attack.t1685, car.2016-04-002
-- Description: Detects command line activity that tries to clear or disable any ETW trace log which could be a sign of logging evasion.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%cl%' AND CommandLine LIKE '%/Trace%')) OR ((CommandLine LIKE '%clear-log%' AND CommandLine LIKE '%/Trace%')) OR ((CommandLine LIKE '%sl%' AND CommandLine LIKE '%/e:false%')) OR ((CommandLine LIKE '%set-log%' AND CommandLine LIKE '%/e:false%')) OR ((CommandLine LIKE '%logman%' AND CommandLine LIKE '%update%' AND CommandLine LIKE '%trace%' AND CommandLine LIKE '%--p%' AND CommandLine LIKE '%-ets%')) OR (CommandLine LIKE '%Remove-EtwTraceProvider%') OR ((CommandLine LIKE '%Set-EtwTraceProvider%' AND CommandLine LIKE '%0x11%')))
