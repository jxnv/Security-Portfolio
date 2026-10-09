-- Title: OpenCanary - SSH New Connection Attempt
-- ID: cd55f721-5623-4663-bd9b-5229cab5237d
-- Status: test
-- Level: high
-- Author: Security Onion Solutions
-- Date: 2024-03-08
-- Tags: attack.privilege-escalation, attack.initial-access, attack.lateral-movement, attack.persistence, attack.stealth, attack.t1133, attack.t1021, attack.t1078
-- Description: Detects instances where an SSH service on an OpenCanary node has had a connection attempt.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (logtype = '4000')
