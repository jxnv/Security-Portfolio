-- Title: Hiding User Account Via SpecialAccounts Registry Key - CommandLine
-- ID: 9ec9fb1b-e059-4489-9642-f270c207923d
-- Status: test
-- Level: medium
-- Author: @Kostastsale, TheDFIRReport
-- Date: 2022-05-14
-- Tags: attack.stealth, attack.t1564.002
-- Description: Detects changes to the registry key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" where the value is set to "0" in order to hide user account from being listed on the logon screen.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%\\reg.exe' AND (CommandLine ILIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList%' AND CommandLine ILIKE '%add%' AND CommandLine ILIKE '%/v%' AND CommandLine ILIKE '%/d 0%'))
