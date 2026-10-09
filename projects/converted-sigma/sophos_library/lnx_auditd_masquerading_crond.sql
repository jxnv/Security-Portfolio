-- Title: Masquerading as Linux Crond Process
-- ID: 9d4548fa-bba0-4e88-bd66-5d5bf516cda0
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2019-10-21
-- Tags: attack.stealth, attack.t1036.003
-- Description: Masquerading occurs when the name or location of an executable, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation.
-- Several different variations of this technique have been observed.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (type = 'execve' AND a0 = 'cp' AND a1 = '/bin/sh' AND a2 ILIKE '%/crond')
