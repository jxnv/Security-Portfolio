-- Title: Python Spawning Pretty TTY Via PTY Module
-- ID: c4042d54-110d-45dd-a0e1-05c47822c937
-- Status: test
-- Level: medium
-- Author: Nextron Systems
-- Date: 2022-06-03
-- Tags: attack.execution, attack.t1059
-- Description: Detects a python process calling to the PTY module in order to spawn a pretty tty which could be indicative of potential reverse shell activity.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%import pty%' OR CommandLine ILIKE '%from pty %')) AND (CommandLine ILIKE '%spawn%') AND (((Image ILIKE '%/python' OR Image ILIKE '%/python2' OR Image ILIKE '%/python3')) OR ((Image ILIKE '%/python2.%' OR Image ILIKE '%/python3.%'))))
