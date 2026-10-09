-- Title: Suspicious ScreenSave Change by Reg.exe
-- ID: 0fc35fc3-efe6-4898-8a37-0b233339524f
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-08-19
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1546.002
-- Description: Adversaries may establish persistence by executing malicious content triggered by user inactivity.
-- Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\reg.exe" AND (CommandLine LIKE '%HKEY_CURRENT_USER\\Control Panel\\Desktop%' OR CommandLine LIKE '%HKCU\\Control Panel\\Desktop%')) AND (((CommandLine LIKE '%/v ScreenSaveActive%' AND CommandLine LIKE '%/t REG_SZ%' AND CommandLine LIKE '%/d 1%' AND CommandLine LIKE '%/f%')) OR ((CommandLine LIKE '%/v ScreenSaveTimeout%' AND CommandLine LIKE '%/t REG_SZ%' AND CommandLine LIKE '%/d %' AND CommandLine LIKE '%/f%')) OR ((CommandLine LIKE '%/v ScreenSaverIsSecure%' AND CommandLine LIKE '%/t REG_SZ%' AND CommandLine LIKE '%/d 0%' AND CommandLine LIKE '%/f%')) OR ((CommandLine LIKE '%/v SCRNSAVE.EXE%' AND CommandLine LIKE '%/t REG_SZ%' AND CommandLine LIKE '%/d %' AND CommandLine LIKE '%.scr%' AND CommandLine LIKE '%/f%'))))
