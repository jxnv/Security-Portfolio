-- Title: ISATAP Router Address Was Set
-- ID: d22df9cd-2aee-4089-93c7-9dc4eae77f2c
-- Status: experimental
-- Level: medium
-- Author: hamid
-- Date: 2025-10-19
-- Tags: attack.impact, attack.credential-access, attack.collection, attack.initial-access, attack.privilege-escalation, attack.execution, attack.t1557, attack.t1565.002
-- Description: Detects the configuration of a new ISATAP router on a Windows host. While ISATAP is a legitimate Microsoft technology for IPv6 transition, unexpected or unauthorized ISATAP router configurations could indicate a potential IPv6 DNS Takeover attack using tools like mitm6.
-- In such attacks, adversaries advertise themselves as DHCPv6 servers and set malicious ISATAP routers to intercept traffic.
-- This detection should be correlated with network baselines and known legitimate ISATAP deployments in your environment.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((EventID = 4100 AND Provider_Name = 'Microsoft-Windows-Iphlpsvc') AND NOT (((IsatapRouter = '127.0.0.1' OR IsatapRouter = '::1'))) AND NOT ((IsatapRouter IS NULL)))
