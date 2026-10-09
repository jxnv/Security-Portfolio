-- Title: Python Spawning Pretty TTY on Windows
-- ID: 480e7e51-e797-47e3-8d72-ebfce65b6d8d
-- Status: test
-- Level: high
-- Author: Nextron Systems
-- Date: 2022-06-03
-- Tags: attack.execution, attack.t1059
-- Description: Detects python spawning a pretty tty
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%python.exe' OR Image ILIKE '%python3.exe' OR Image ILIKE '%python2.exe')) AND (((CommandLine ILIKE '%import pty%' AND CommandLine ILIKE '%.spawn(%')) OR (CommandLine ILIKE '%from pty import spawn%')))
