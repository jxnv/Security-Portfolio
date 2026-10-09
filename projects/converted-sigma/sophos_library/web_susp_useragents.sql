-- Title: Suspicious User-Agents Related To Recon Tools
-- ID: 19aa4f58-94ca-45ff-bc34-92e533c0994a
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Tim Shelton
-- Date: 2022-07-19
-- Tags: attack.initial-access, attack.t1190
-- Description: Detects known suspicious (default) user-agents related to scanning/recon tools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((cs-user-agent ILIKE '%commix/%' OR cs-user-agent ILIKE '%feroxbuster/%' OR cs-user-agent ILIKE '%Fuzz Faster U Fool%' OR cs-user-agent ILIKE '%GIS - AppSec Team - Project Vision%' OR cs-user-agent ILIKE '%gobuster/%' OR cs-user-agent ILIKE '%Nikto/%' OR cs-user-agent ILIKE '%Nmap Scripting Engine%' OR cs-user-agent ILIKE '%Recon-ng/v%' OR cs-user-agent ILIKE '%sqlmap/%' OR cs-user-agent ILIKE '%WhatWeb/%' OR cs-user-agent ILIKE '%Wfuzz/%' OR cs-user-agent ILIKE '%WPScan v%' OR cs-user-agent ILIKE '%zgrab/%'))
