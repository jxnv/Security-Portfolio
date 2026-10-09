-- Title: Suspicious Msiexec Execute Arbitrary DLL
-- ID: 6f4191bb-912b-48a8-9ce7-682769541e6d
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-01-16
-- Tags: attack.stealth, attack.t1218.007
-- Description: Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
-- Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\msiexec.exe" AND CommandLine LIKE '% /Y%') AND NOT (((CommandLine LIKE '%\\MsiExec.exe\" /Y \"C:\\Program Files\\%' OR CommandLine LIKE '%\\MsiExec.exe\" /Y \"C:\\Program Files (x86)\\%' OR CommandLine LIKE '%\\MsiExec.exe\" /Y \"C:\\Windows\\System32\\%' OR CommandLine LIKE '%\\MsiExec.exe\" /Y \"C:\\Windows\\SysWOW64\\%'))))
