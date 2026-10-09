-- Title: Credentials In Files
-- ID: 53b1b378-9b06-4992-b972-dde6e423d2b4
-- Status: test
-- Level: high
-- Author: Igor Fits, Mikhail Larin, oscd.community
-- Date: 2020-10-19
-- Tags: attack.credential-access, attack.t1552.001
-- Description: Detecting attempts to extract passwords with grep and laZagne
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%/grep' AND CommandLine ILIKE '%password%') OR (CommandLine ILIKE '%laZagne%'))
