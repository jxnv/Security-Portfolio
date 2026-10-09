-- Title: DLL Execution via Rasautou.exe
-- ID: cd3d1298-eb3b-476c-ac67-12847de55813
-- Status: test
-- Level: medium
-- Author: Julia Fomina, oscd.community
-- Date: 2020-10-09
-- Tags: attack.stealth, attack.t1218
-- Description: Detects using Rasautou.exe for loading arbitrary .DLL specified in -d option and executes the export specified in -p.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% -d %' AND CommandLine ILIKE '% -p %')) AND ((Image ILIKE '%\\rasautou.exe') OR (OriginalFileName = 'rasdlui.exe')))
