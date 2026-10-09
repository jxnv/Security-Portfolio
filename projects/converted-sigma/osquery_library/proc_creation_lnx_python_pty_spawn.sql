-- Title: Python Spawning Pretty TTY Via PTY Module
-- ID: c4042d54-110d-45dd-a0e1-05c47822c937
-- Status: test
-- Level: medium
-- Author: Nextron Systems
-- Date: 2022-06-03
-- Tags: attack.execution, attack.t1059
-- Description: Detects a python process calling to the PTY module in order to spawn a pretty tty which could be indicative of potential reverse shell activity.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%import pty%' OR CommandLine LIKE '%from pty %')) AND (CommandLine LIKE '%spawn%') AND (((Image="*/python" OR Image="*/python2" OR Image="*/python3")) OR ((Image LIKE '%/python2.%' OR Image LIKE '%/python3.%'))))
