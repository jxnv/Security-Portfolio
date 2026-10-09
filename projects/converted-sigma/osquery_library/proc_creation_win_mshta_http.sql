-- Title: Remotely Hosted HTA File Executed Via Mshta.EXE
-- ID: b98d0db6-511d-45de-ad02-e82a98729620
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-08
-- Tags: attack.execution, attack.stealth, attack.t1218.005
-- Description: Detects execution of the "mshta" utility with an argument containing the "http" keyword, which could indicate that an attacker is executing a remotely hosted malicious hta file
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%http://%' OR CommandLine LIKE '%https://%' OR CommandLine LIKE '%ftp://%')) AND ((Image="*\\mshta.exe") OR (OriginalFileName = 'MSHTA.EXE')))
