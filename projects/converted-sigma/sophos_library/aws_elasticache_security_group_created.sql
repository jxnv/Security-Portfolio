-- Title: AWS ElastiCache Security Group Created
-- ID: 4ae68615-866f-4304-b24b-ba048dfa5ca7
-- Status: test
-- Level: low
-- Author: Austin Songer @austinsonger
-- Date: 2021-07-24
-- Tags: attack.persistence, attack.t1136, attack.t1136.003
-- Description: Detects when an ElastiCache security group has been created.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (eventSource = 'elasticache.amazonaws.com' AND eventName = 'CreateCacheSecurityGroup')
