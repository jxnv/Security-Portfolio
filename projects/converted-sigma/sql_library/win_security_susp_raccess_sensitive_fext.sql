-- Title: Suspicious Access to Sensitive File Extensions
-- ID: 91c945bc-2ad1-4799-a591-4d00198a1215
-- Status: test
-- Level: medium
-- Author: Samir Bousseaden
-- Date: 2019-04-03
-- Tags: attack.collection, attack.t1039
-- Description: Detects known sensitive file extensions accessed on a network share
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventID = 5145 AND (RelativeTargetName ILIKE '%.bak' OR RelativeTargetName ILIKE '%.dmp' OR RelativeTargetName ILIKE '%.edb' OR RelativeTargetName ILIKE '%.kirbi' OR RelativeTargetName ILIKE '%.msg' OR RelativeTargetName ILIKE '%.nsf' OR RelativeTargetName ILIKE '%.nst' OR RelativeTargetName ILIKE '%.oab' OR RelativeTargetName ILIKE '%.ost' OR RelativeTargetName ILIKE '%.pst' OR RelativeTargetName ILIKE '%.rdp'))
