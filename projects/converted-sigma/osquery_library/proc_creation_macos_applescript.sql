-- Title: MacOS Scripting Interpreter AppleScript
-- ID: 1bc2e6c5-0885-472b-bed6-be5ea8eace55
-- Status: test
-- Level: medium
-- Author: Alejandro Ortuno, oscd.community
-- Date: 2020-10-21
-- Tags: attack.execution, attack.t1059.002
-- Description: Detects execution of AppleScript of the macOS scripting language AppleScript.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/osascript" AND (CommandLine LIKE '% -e %' OR CommandLine LIKE '%.scpt%' OR CommandLine LIKE '%.js%')) AND NOT ((ParentImage="*opencode" AND (CommandLine LIKE '%osascript%' AND CommandLine LIKE '% -e %' AND CommandLine LIKE '%set imageData to the clipboard%' AND CommandLine LIKE '%set fileRef%'))))
