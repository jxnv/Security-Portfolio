-- Title: Potentially Suspicious Child Process Of Regsvr32
-- ID: 6f0947a4-1c5e-4e0d-8ac7-53159b8f23ca
-- Status: test
-- Level: high
-- Author: elhoim, Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-05-05
-- Tags: attack.stealth, attack.t1218.010
-- Description: Detects potentially suspicious child processes of "regsvr32.exe".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ParentImage ILIKE '%\\regsvr32.exe' AND (Image ILIKE '%\\calc.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\explorer.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe' OR Image ILIKE '%\\nltest.exe' OR Image ILIKE '%\\notepad.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\reg.exe' OR Image ILIKE '%\\schtasks.exe' OR Image ILIKE '%\\werfault.exe' OR Image ILIKE '%\\wscript.exe')) AND NOT ((Image ILIKE '%\\werfault.exe' AND CommandLine ILIKE '% -u -p %')))
