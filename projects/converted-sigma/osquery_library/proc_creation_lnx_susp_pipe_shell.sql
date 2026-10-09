-- Title: Linux Shell Pipe to Shell
-- ID: 880973f3-9708-491c-a77b-2a35a1921158
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-14
-- Tags: attack.stealth, attack.t1140
-- Description: Detects suspicious process command line that starts with a shell that executes something and finally gets piped into another shell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine="sh -c *" OR CommandLine="bash -c *")) AND (((CommandLine LIKE '%| bash %' OR CommandLine LIKE '%| sh %' OR CommandLine LIKE '%|bash %' OR CommandLine LIKE '%|sh %')) OR ((CommandLine="*| bash" OR CommandLine="*| sh" OR CommandLine="*|bash" OR CommandLine="* |sh"))))
