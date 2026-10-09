-- Title: Suspicious SysAidServer Child
-- ID: 60bfeac3-0d35-4302-8efb-1dd16f715bc6
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-26
-- Tags: attack.lateral-movement, attack.t1210
-- Description: Detects suspicious child processes of SysAidServer (as seen in MERCURY threat actor intrusions)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\java.exe' OR ParentImage ILIKE '%\\javaw.exe') AND ParentCommandLine ILIKE '%SysAidServer%')
