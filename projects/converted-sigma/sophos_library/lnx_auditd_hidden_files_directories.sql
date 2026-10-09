-- Title: Hidden Files and Directories
-- ID: d08722cd-3d09-449a-80b4-83ea2d9d4616
-- Status: test
-- Level: low
-- Author: Pawel Mazur
-- Date: 2021-09-06
-- Tags: attack.stealth, attack.t1564.001
-- Description: Detects adversary creating hidden file or directory, by detecting directories or files with . as the first character
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((REGEXP_LIKE(a1, '(^|\/)\.[^.\/]')) OR (REGEXP_LIKE(a2, '(^|\/)\.[^.\/]'))) AND (type = 'EXECVE' AND (a0 = 'mkdir' OR a0 = 'nano' OR a0 = 'touch' OR a0 = 'vi' OR a0 = 'vim')))
