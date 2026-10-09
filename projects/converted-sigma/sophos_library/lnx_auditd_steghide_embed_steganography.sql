-- Title: Steganography Hide Files with Steghide
-- ID: ce446a9e-30b9-4483-8e38-d2c9ad0a2280
-- Status: test
-- Level: low
-- Author: Pawel Mazur
-- Date: 2021-09-11
-- Tags: attack.stealth, attack.t1027.003
-- Description: Detects embedding of files with usage of steghide binary, the adversaries may use this technique to prevent the detection of hidden information.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (type = 'EXECVE' AND a0 = 'steghide' AND a1 = 'embed' AND (a2 = '-cf' OR a2 = '-ef') AND (a4 = '-cf' OR a4 = '-ef'))
