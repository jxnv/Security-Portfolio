-- Title: Use of W32tm as Timer
-- ID: 6da2c9f5-7c53-401b-aacb-92c040ce1215
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-09-25
-- Tags: attack.discovery, attack.t1124
-- Description: When configured with suitable command line arguments, w32tm can act as a delay mechanism
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%/stripchart%' AND CommandLine ILIKE '%/computer:%' AND CommandLine ILIKE '%/period:%' AND CommandLine ILIKE '%/dataonly%' AND CommandLine ILIKE '%/samples:%')) AND ((Image ILIKE '%\\w32tm.exe') OR (OriginalFileName = 'w32time.dll')))
