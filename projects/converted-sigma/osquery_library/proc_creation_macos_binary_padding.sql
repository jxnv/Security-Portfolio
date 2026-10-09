-- Title: Binary Padding - MacOS
-- ID: 95361ce5-c891-4b0a-87ca-e24607884a96
-- Status: test
-- Level: high
-- Author: Igor Fits, Mikhail Larin, oscd.community
-- Date: 2020-10-19
-- Tags: attack.stealth, attack.t1027.001
-- Description: Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This rule detect using dd and truncate to add a junk data to file.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/dd" AND (CommandLine LIKE '%if=/dev/zero%' OR CommandLine LIKE '%if=/dev/random%' OR CommandLine LIKE '%if=/dev/urandom%')) OR (Image="*/truncate" AND CommandLine LIKE '%-s +%'))
