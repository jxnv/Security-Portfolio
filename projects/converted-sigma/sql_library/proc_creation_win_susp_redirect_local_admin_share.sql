-- Title: Suspicious Redirection to Local Admin Share
-- ID: ab9e3b40-0c85-4ba1-aede-455d226fd124
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-01-16
-- Tags: attack.exfiltration, attack.t1048
-- Description: Detects a suspicious output redirection to the local admins share, this technique is often found in malicious scripts or hacktool stagers
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%>%') AND ((CommandLine ILIKE '%\\\\\\\\127.0.0.1\\\\admin$\\\\%' OR CommandLine ILIKE '%\\\\\\\\localhost\\\\admin$\\\\%')))
