-- Title: Suspicious User-Agents Related To Recon Tools
-- ID: 19aa4f58-94ca-45ff-bc34-92e533c0994a
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Tim Shelton
-- Date: 2022-07-19
-- Tags: attack.initial-access, attack.t1190
-- Description: Detects known suspicious (default) user-agents related to scanning/recon tools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((cs-user-agent LIKE '%commix/%' OR cs-user-agent LIKE '%feroxbuster/%' OR cs-user-agent LIKE '%Fuzz Faster U Fool%' OR cs-user-agent LIKE '%GIS - AppSec Team - Project Vision%' OR cs-user-agent LIKE '%gobuster/%' OR cs-user-agent LIKE '%Nikto/%' OR cs-user-agent LIKE '%Nmap Scripting Engine%' OR cs-user-agent LIKE '%Recon-ng/v%' OR cs-user-agent LIKE '%sqlmap/%' OR cs-user-agent LIKE '%WhatWeb/%' OR cs-user-agent LIKE '%Wfuzz/%' OR cs-user-agent LIKE '%WPScan v%' OR cs-user-agent LIKE '%zgrab/%'))
