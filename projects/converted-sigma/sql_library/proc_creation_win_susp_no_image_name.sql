-- Title: Process Launched Without Image Name
-- ID: f208d6d8-d83a-4c2c-960d-877c37da84e5
-- Status: test
-- Level: medium
-- Author: Matt Anderson (Huntress)
-- Date: 2024-07-23
-- Tags: attack.stealth
-- Description: Detect the use of processes with no name (".exe"), which can be used to evade Image-based detections.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%\\.exe')
