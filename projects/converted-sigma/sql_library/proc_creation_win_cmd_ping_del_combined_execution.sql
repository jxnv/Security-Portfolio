-- Title: Suspicious Ping/Del Command Combination
-- ID: 54786ddc-5b8a-11ed-9b6a-0242ac120002
-- Status: test
-- Level: high
-- Author: Ilya Krestinichev
-- Date: 2022-11-03
-- Tags: attack.stealth, attack.t1070.004
-- Description: Detects a method often used by ransomware. Which combines the "ping" to wait a couple of seconds and then "del" to delete the file in question. Its used to hide the file responsible for the initial infection for example
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%ping%' AND CommandLine ILIKE '%del %')) AND (CommandLine ILIKE '% -n %') AND ((CommandLine ILIKE '% -f %' OR CommandLine ILIKE '% -q %')) AND (CommandLine ILIKE '%Nul%'))
