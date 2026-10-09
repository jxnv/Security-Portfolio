-- Title: Potential Persistence Attempt Via Run Keys Using Reg.EXE
-- ID: de587dce-915e-4218-aac4-835ca6af6f70
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2021-06-28
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects suspicious command line reg.exe tool adding key to RUN key in Registry
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%\\reg.exe' AND (CommandLine ILIKE '%reg%' AND CommandLine ILIKE '% add %') AND (CommandLine ILIKE '%Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR CommandLine ILIKE '%\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run%' OR CommandLine ILIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%'))
