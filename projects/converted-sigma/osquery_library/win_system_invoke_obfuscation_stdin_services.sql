-- Title: Invoke-Obfuscation STDIN+ Launcher - System
-- ID: 72862bf2-0eb1-11eb-adc1-0242ac120002
-- Status: test
-- Level: high
-- Author: Jonathan Cheong, oscd.community
-- Date: 2020-10-15
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated use of stdin to execute PowerShell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Provider_Name = 'Service Control Manager' AND EventID = '7045' AND (ImagePath LIKE '%cmd%' AND ImagePath LIKE '%powershell%') AND (ImagePath LIKE '%/c%' OR ImagePath LIKE '%/r%')) AND ((ImagePath LIKE '%noexit%') OR ((ImagePath LIKE '%input%' AND ImagePath LIKE '%$%'))))
