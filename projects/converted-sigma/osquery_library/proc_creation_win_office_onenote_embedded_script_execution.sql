-- Title: OneNote.EXE Execution of Malicious Embedded Scripts
-- ID: 84b1706c-932a-44c4-ae28-892b28a25b94
-- Status: test
-- Level: high
-- Author: @kostastsale
-- Date: 2023-02-02
-- Tags: attack.stealth, attack.t1218.001
-- Description: Detects the execution of malicious OneNote documents that contain embedded scripts.
-- When a user clicks on a OneNote attachment and then on the malicious link inside the ".one" file, it exports and executes the malicious embedded script from specific directories.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (ParentImage="*\\onenote.exe" AND (Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wscript.exe") AND (CommandLine LIKE '%\\exported\\%' OR CommandLine LIKE '%\\onenoteofflinecache_files\\%'))
