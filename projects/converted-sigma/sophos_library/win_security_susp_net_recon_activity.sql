-- Title: Reconnaissance Activity
-- ID: 968eef52-9cff-4454-8992-1e74b9cbad6c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Jack Croock (method), Jonhnathan Ribeiro (improvements), oscd.community
-- Date: 2017-03-07
-- Tags: attack.discovery, attack.t1087.002, attack.t1069.002, attack.s0039
-- Description: Detects activity as "net user administrator /domain" and "net group domain admins /domain"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (EventID = 4661 AND AccessMask = '0x2d' AND (ObjectType = 'SAM_USER' OR ObjectType = 'SAM_GROUP') AND ObjectName ILIKE 'S-1-5-21-%' AND (ObjectName ILIKE '%-500' OR ObjectName ILIKE '%-512'))
