-- Title: Suspicious MacOS Firmware Activity
-- ID: 7ed2c9f7-c59d-4c82-a7e2-f859aa676099
-- Status: test
-- Level: medium
-- Author: Austin Songer @austinsonger
-- Date: 2021-09-30
-- Tags: attack.impact
-- Description: Detects when a user manipulates with Firmward Password on MacOS. NOTE - this command has been disabled on silicon-based apple computers.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image = '/usr/sbin/firmwarepasswd' AND (CommandLine ILIKE '%setpasswd%' OR CommandLine ILIKE '%full%' OR CommandLine ILIKE '%delete%' OR CommandLine ILIKE '%check%'))
