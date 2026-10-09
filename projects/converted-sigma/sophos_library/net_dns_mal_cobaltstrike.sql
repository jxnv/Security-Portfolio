-- Title: Cobalt Strike DNS Beaconing
-- ID: 2975af79-28c4-4d2f-a951-9095f229df29
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2018-05-10
-- Tags: attack.command-and-control, attack.t1071.004
-- Description: Detects suspicious DNS queries known from Cobalt Strike beacons
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((query ILIKE 'aaa.stage.%' OR query ILIKE 'post.1%')) OR (query ILIKE '%.stage.123456.%'))
