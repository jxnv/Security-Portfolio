-- Title: Domain Trust Discovery Via Dsquery
-- ID: 3bad990e-4848-4a78-9530-b427d854aac0
-- Status: test
-- Level: medium
-- Author: E.M. Anhaus, Tony Lambert, oscd.community, omkar72
-- Date: 2019-10-24
-- Tags: attack.discovery, attack.t1482
-- Description: Detects execution of "dsquery.exe" for domain trust discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%trustedDomain%') AND ((Image ILIKE '%\\dsquery.exe') OR (OriginalFileName = 'dsquery.exe')))
