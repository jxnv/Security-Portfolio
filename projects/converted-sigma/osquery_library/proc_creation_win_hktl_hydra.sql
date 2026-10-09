-- Title: HackTool - Hydra Password Bruteforce Execution
-- ID: aaafa146-074c-11eb-adc1-0242ac120002
-- Status: test
-- Level: high
-- Author: Vasiliy Burov
-- Date: 2020-10-05
-- Tags: attack.credential-access, attack.t1110, attack.t1110.001
-- Description: Detects command line parameters used by Hydra password guessing hack tool
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%-u %' AND CommandLine LIKE '%-p %') AND (CommandLine LIKE '%^USER^%' OR CommandLine LIKE '%^PASS^%'))
