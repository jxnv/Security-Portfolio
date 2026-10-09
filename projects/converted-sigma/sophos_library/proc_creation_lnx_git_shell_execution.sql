-- Title: Shell Execution via Git - Linux
-- ID: 47b3bbd4-1bf7-48cc-84ab-995362aaa75a
-- Status: test
-- Level: high
-- Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date: 2024-09-02
-- Tags: attack.execution, attack.t1059
-- Description: Detects the use of the "git" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ParentImage ILIKE '%/git' AND (ParentCommandLine ILIKE '% -p %' AND ParentCommandLine ILIKE '%help%') AND (CommandLine ILIKE '%bash 0<&1%' OR CommandLine ILIKE '%dash 0<&1%' OR CommandLine ILIKE '%sh 0<&1%'))
