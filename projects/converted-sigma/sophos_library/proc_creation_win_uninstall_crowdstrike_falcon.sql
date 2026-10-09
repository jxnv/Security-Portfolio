-- Title: Uninstall Crowdstrike Falcon Sensor
-- ID: f0f7be61-9cf5-43be-9836-99d6ef448a18
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2021-07-12
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%\\WindowsSensor.exe%' AND CommandLine ILIKE '% /uninstall%' AND CommandLine ILIKE '% /quiet%'))
