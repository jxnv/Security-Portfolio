-- Title: Suspicious Workstation Locking via Rundll32
-- ID: 3b5b0213-0460-4e3f-8937-3abf98ff7dcc
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-06-04
-- Tags: attack.stealth
-- Description: Detects a suspicious call to the user32.dll function that locks the user workstation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%user32.dll,%') AND ((Image ILIKE '%\\rundll32.exe') OR (OriginalFileName = 'RUNDLL32.EXE')) AND (ParentImage ILIKE '%\\cmd.exe') AND (CommandLine ILIKE '%LockWorkStation%'))
