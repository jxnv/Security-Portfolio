-- Title: GUI Input Capture - macOS
-- ID: 60f1ce20-484e-41bd-85f4-ac4afec2c541
-- Status: test
-- Level: low
-- Author: remotephone, oscd.community
-- Date: 2020-10-13
-- Tags: attack.collection, attack.credential-access, attack.t1056.002
-- Description: Detects attempts to use system dialog prompts to capture user credentials
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%-e%' AND CommandLine ILIKE '%display%' AND CommandLine ILIKE '%dialog%' AND CommandLine ILIKE '%answer%')) AND ((CommandLine ILIKE '%admin%' OR CommandLine ILIKE '%administrator%' OR CommandLine ILIKE '%authenticate%' OR CommandLine ILIKE '%authentication%' OR CommandLine ILIKE '%credentials%' OR CommandLine ILIKE '%pass%' OR CommandLine ILIKE '%password%' OR CommandLine ILIKE '%unlock%')) AND (Image ILIKE '%/osascript'))
