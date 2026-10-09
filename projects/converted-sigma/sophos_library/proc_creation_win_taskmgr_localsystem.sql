-- Title: Taskmgr as LOCAL_SYSTEM
-- ID: 9fff585c-c33e-4a86-b3cd-39312079a65f
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2018-03-18
-- Tags: attack.stealth, attack.t1036
-- Description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((User ILIKE '%AUTHORI%' OR User ILIKE '%AUTORI%') AND Image ILIKE '%\\taskmgr.exe')
