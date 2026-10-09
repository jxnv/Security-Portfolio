-- Title: Execute Files with Msdeploy.exe
-- ID: 646bc99f-6682-4b47-a73a-17b1b64c9d34
-- Status: test
-- Level: medium
-- Author: Beyu Denis, oscd.community
-- Date: 2020-10-18
-- Tags: attack.stealth, attack.t1218
-- Description: Detects file execution using the msdeploy.exe lolbin
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%verb:sync%' AND CommandLine ILIKE '%-source:RunCommand%' AND CommandLine ILIKE '%-dest:runCommand%') AND Image ILIKE '%\\msdeploy.exe')
