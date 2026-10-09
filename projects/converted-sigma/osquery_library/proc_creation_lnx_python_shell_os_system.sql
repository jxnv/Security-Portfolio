-- Title: Inline Python Execution - Spawn Shell Via OS System Library
-- ID: 2d2f44ff-4611-4778-a8fc-323a0e9850cc
-- Status: test
-- Level: high
-- Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date: 2024-09-02
-- Tags: attack.execution, attack.t1059
-- Description: Detects execution of inline Python code via the "-c" in order to call the "system" function from the "os" library, and spawn a shell.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% -c %' AND CommandLine LIKE '%os.system(%') AND (CommandLine LIKE '%/bin/bash%' OR CommandLine LIKE '%/bin/dash%' OR CommandLine LIKE '%/bin/fish%' OR CommandLine LIKE '%/bin/sh%' OR CommandLine LIKE '%/bin/zsh%')) AND (((Image="*/python" OR Image="*/python2" OR Image="*/python3")) OR ((Image LIKE '%/python2.%' OR Image LIKE '%/python3.%'))))
