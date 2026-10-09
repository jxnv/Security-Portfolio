-- Title: Invoke-Obfuscation STDIN+ Launcher - Powershell
-- ID: 779c8c12-0eb1-11eb-adc1-0242ac120002
-- Status: test
-- Level: high
-- Author: Jonathan Cheong, oscd.community
-- Date: 2020-10-15
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated use of stdin to execute PowerShell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (ScriptBlockText=regex("cmd.{0,5}(?:/c|/r).+powershell.+(?:\\$?\\{?input\\}?|noexit).+\""))
