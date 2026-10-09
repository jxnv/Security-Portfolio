-- Title: ETW Trace Evasion Activity
-- ID: a238b5d0-ce2d-4414-a676-7a531b3d13d6
-- Status: test
-- Level: high
-- Author: @neu5ron, Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
-- Date: 2019-03-22
-- Tags: attack.stealth, attack.defense-impairment, attack.t1070, attack.t1685, car.2016-04-002
-- Description: Detects command line activity that tries to clear or disable any ETW trace log which could be a sign of logging evasion.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%cl%' AND CommandLine ILIKE '%/Trace%')) OR ((CommandLine ILIKE '%clear-log%' AND CommandLine ILIKE '%/Trace%')) OR ((CommandLine ILIKE '%sl%' AND CommandLine ILIKE '%/e:false%')) OR ((CommandLine ILIKE '%set-log%' AND CommandLine ILIKE '%/e:false%')) OR ((CommandLine ILIKE '%logman%' AND CommandLine ILIKE '%update%' AND CommandLine ILIKE '%trace%' AND CommandLine ILIKE '%--p%' AND CommandLine ILIKE '%-ets%')) OR (CommandLine ILIKE '%Remove-EtwTraceProvider%') OR ((CommandLine ILIKE '%Set-EtwTraceProvider%' AND CommandLine ILIKE '%0x11%')))
