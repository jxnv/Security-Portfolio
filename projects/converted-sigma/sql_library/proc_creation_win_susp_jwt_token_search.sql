-- Title: Potentially Suspicious JWT Token Search Via CLI
-- ID: 6d3a3952-6530-44a3-8554-cf17c116c615
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), kagebunsher
-- Date: 2022-10-25
-- Tags: attack.credential-access, attack.t1528, attack.t1552.001
-- Description: Detects potentially suspicious search for JWT tokens via CLI by looking for the string "eyJ0eX" or "eyJhbG".
-- JWT tokens are often used for access-tokens across various applications and services like Microsoft 365, Azure, AWS, Google Cloud, and others.
-- Threat actors may search for these tokens to steal them for lateral movement or privilege escalation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%eyJ0eXAiOi%' OR CommandLine ILIKE '%eyJhbGciOi%' OR CommandLine ILIKE '% eyJ0eX%' OR CommandLine ILIKE '% \"eyJ0eX\"%' OR CommandLine ILIKE '% 'eyJ0eX'%' OR CommandLine ILIKE '% eyJhbG%' OR CommandLine ILIKE '% \"eyJhbG\"%' OR CommandLine ILIKE '% 'eyJhbG'%')) AND ((CommandLine ILIKE '%find %' OR CommandLine ILIKE '%find.exe%' OR CommandLine ILIKE '%findstr%' OR CommandLine ILIKE '%select-string %' OR CommandLine ILIKE '%strings%')))
