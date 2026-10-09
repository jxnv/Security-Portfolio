-- Title: MacOS Scripting Interpreter AppleScript
-- ID: 1bc2e6c5-0885-472b-bed6-be5ea8eace55
-- Status: test
-- Level: medium
-- Author: Alejandro Ortuno, oscd.community
-- Date: 2020-10-21
-- Tags: attack.execution, attack.t1059.002
-- Description: Detects execution of AppleScript of the macOS scripting language AppleScript.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%/osascript' AND (CommandLine ILIKE '% -e %' OR CommandLine ILIKE '%.scpt%' OR CommandLine ILIKE '%.js%')) AND NOT ((ParentImage ILIKE '%opencode' AND (CommandLine ILIKE '%osascript%' AND CommandLine ILIKE '% -e %' AND CommandLine ILIKE '%set imageData to the clipboard%' AND CommandLine ILIKE '%set fileRef%'))))
