-- Title: Indicator Removal on Host - Clear Mac System Logs
-- ID: acf61bd8-d814-4272-81f0-a7a269aa69aa
-- Status: test
-- Level: medium
-- Author: remotephone, oscd.community
-- Date: 2020-10-11
-- Tags: attack.defense-impairment, attack.t1685.006
-- Description: Detects deletion of local audit logs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%/rm' OR Image ILIKE '%/unlink' OR Image ILIKE '%/shred')) AND ((CommandLine ILIKE '%/var/log%') OR ((CommandLine ILIKE '%/Users/%' AND CommandLine ILIKE '%/Library/Logs/%'))))
