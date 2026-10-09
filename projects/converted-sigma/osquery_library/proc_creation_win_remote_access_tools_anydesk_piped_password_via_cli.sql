-- Title: Remote Access Tool - AnyDesk Piped Password Via CLI
-- ID: b1377339-fda6-477a-b455-ac0923f9ec2c
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-28
-- Tags: attack.command-and-control, attack.t1219.002
-- Description: Detects piping the password to an anydesk instance via CMD and the '--set-password' flag.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%/c %' AND CommandLine LIKE '%echo %' AND CommandLine LIKE '%.exe --set-password%'))
