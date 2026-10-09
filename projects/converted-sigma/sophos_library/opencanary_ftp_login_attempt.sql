-- Title: OpenCanary - FTP Login Attempt
-- ID: 6991bc2b-ae2e-447f-bc55-3a1ba04c14e5
-- Status: test
-- Level: high
-- Author: Security Onion Solutions
-- Date: 2024-03-08
-- Tags: attack.initial-access, attack.exfiltration, attack.lateral-movement, attack.t1190, attack.t1021
-- Description: Detects instances where an FTP service on an OpenCanary node has had a login attempt.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (logtype = 2000)
