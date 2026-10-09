-- Title: GUI Input Capture - macOS
-- ID: 60f1ce20-484e-41bd-85f4-ac4afec2c541
-- Status: test
-- Level: low
-- Author: remotephone, oscd.community
-- Date: 2020-10-13
-- Tags: attack.collection, attack.credential-access, attack.t1056.002
-- Description: Detects attempts to use system dialog prompts to capture user credentials
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%-e%' AND CommandLine LIKE '%display%' AND CommandLine LIKE '%dialog%' AND CommandLine LIKE '%answer%')) AND ((CommandLine LIKE '%admin%' OR CommandLine LIKE '%administrator%' OR CommandLine LIKE '%authenticate%' OR CommandLine LIKE '%authentication%' OR CommandLine LIKE '%credentials%' OR CommandLine LIKE '%pass%' OR CommandLine LIKE '%password%' OR CommandLine LIKE '%unlock%')) AND (Image="*/osascript"))
