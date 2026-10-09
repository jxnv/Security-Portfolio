-- Title: Screen Capture Activity Via Psr.EXE
-- ID: 2158f96f-43c2-43cb-952a-ab4580f32382
-- Status: test
-- Level: medium
-- Author: Beyu Denis, oscd.community
-- Date: 2019-10-12
-- Tags: attack.collection, attack.t1113
-- Description: Detects execution of Windows Problem Steps Recorder (psr.exe), a utility used to record the user screen and clicks.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%\\Psr.exe' AND (CommandLine ILIKE '%/start%' OR CommandLine ILIKE '%-start%'))
