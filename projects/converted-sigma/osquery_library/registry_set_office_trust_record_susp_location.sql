-- Title: Macro Enabled In A Potentially Suspicious Document
-- ID: a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-06-21
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects registry changes to Office trust records where the path is located in a potentially suspicious location
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetObject LIKE '%/AppData/Local/Microsoft/Windows/INetCache/%' OR TargetObject LIKE '%/AppData/Local/Temp/%' OR TargetObject LIKE '%/PerfLogs/%' OR TargetObject LIKE '%C:/Users/Public/%' OR TargetObject LIKE '%file:///D:/%' OR TargetObject LIKE '%file:///E:/%')) AND (TargetObject LIKE '%\\Security\\Trusted Documents\\TrustRecords%'))
