-- Title: Bypass UAC via CMSTP
-- ID: e66779cc-383e-4224-a3a4-267eeb585c40
-- Status: test
-- Level: high
-- Author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
-- Date: 2019-10-24
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1548.002, attack.t1218.003
-- Description: Detect commandline usage of Microsoft Connection Manager Profile Installer (cmstp.exe) to install specially formatted local .INF files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%/s%' OR CommandLine ILIKE '%-s%' OR CommandLine ILIKE '%/au%' OR CommandLine ILIKE '%-au%' OR CommandLine ILIKE '%/ni%' OR CommandLine ILIKE '%-ni%')) AND ((Image ILIKE '%\\cmstp.exe') OR (OriginalFileName = 'CMSTP.EXE')))
