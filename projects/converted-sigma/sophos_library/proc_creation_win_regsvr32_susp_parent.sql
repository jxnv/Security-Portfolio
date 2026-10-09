-- Title: Scripting/CommandLine Process Spawned Regsvr32
-- ID: ab37a6ec-6068-432b-a64e-2c7bf95b1d22
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-26
-- Tags: attack.stealth, attack.t1218.010
-- Description: Detects various command line and scripting engines/processes such as "PowerShell", "Wscript", "Cmd", etc. spawning a "regsvr32" instance.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentImage ILIKE '%\\cmd.exe' OR ParentImage ILIKE '%\\cscript.exe' OR ParentImage ILIKE '%\\mshta.exe' OR ParentImage ILIKE '%\\powershell_ise.exe' OR ParentImage ILIKE '%\\powershell.exe' OR ParentImage ILIKE '%\\pwsh.exe' OR ParentImage ILIKE '%\\wscript.exe') AND Image ILIKE '%\\regsvr32.exe') AND NOT ((ParentImage = 'C:\\Windows\\System32\\cmd.exe' AND CommandLine ILIKE '% /s C:\\Windows\\System32\\RpcProxy\\RpcProxy.dll')))
