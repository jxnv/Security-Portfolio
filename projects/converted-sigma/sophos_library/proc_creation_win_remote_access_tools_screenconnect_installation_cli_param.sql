-- Title: Remote Access Tool - ScreenConnect Installation Execution
-- ID: 75bfe6e6-cd8e-429e-91d3-03921e1d7962
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-02-11
-- Tags: attack.persistence, attack.initial-access, attack.t1133
-- Description: Detects ScreenConnect program starts that establish a remote access to a system.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%e=Access&%' AND CommandLine ILIKE '%y=Guest&%' AND CommandLine ILIKE '%&p=%' AND CommandLine ILIKE '%&c=%' AND CommandLine ILIKE '%&k=%'))
