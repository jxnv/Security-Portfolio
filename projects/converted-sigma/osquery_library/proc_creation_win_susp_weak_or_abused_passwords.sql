-- Title: Weak or Abused Passwords In CLI
-- ID: 91edcfb1-2529-4ac2-9ecc-7617f895c7e4
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-14
-- Tags: attack.execution, attack.stealth
-- Description: Detects weak passwords or often abused passwords (seen used by threat actors) via the CLI.
-- An example would be a threat actor creating a new user via the net command and providing the password inline
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%123456789%' OR CommandLine LIKE '%123123qwE%' OR CommandLine LIKE '%Asd123.aaaa%' OR CommandLine LIKE '%Decryptme%' OR CommandLine LIKE '%P@ssw0rd!%' OR CommandLine LIKE '%Pass8080%' OR CommandLine LIKE '%password123%' OR CommandLine LIKE '%test@202%'))
