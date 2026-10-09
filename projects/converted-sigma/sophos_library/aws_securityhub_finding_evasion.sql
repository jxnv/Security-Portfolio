-- Title: AWS SecurityHub Findings Evasion
-- ID: a607e1fe-74bf-4440-a3ec-b059b9103157
-- Status: stable
-- Level: high
-- Author: Sittikorn S
-- Date: 2021-06-28
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects the modification of the findings on SecurityHub.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (eventSource = 'securityhub.amazonaws.com' AND (eventName = 'BatchUpdateFindings' OR eventName = 'DeleteInsight' OR eventName = 'UpdateFindings' OR eventName = 'UpdateInsight'))
