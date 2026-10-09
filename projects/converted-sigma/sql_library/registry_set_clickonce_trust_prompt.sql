-- Title: ClickOnce Trust Prompt Tampering
-- ID: ac9159cc-c364-4304-8f0a-d63fc1a0aabb
-- Status: test
-- Level: medium
-- Author: @SerkinValery, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-06-12
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects changes to the ClickOnce trust prompt registry key in order to enable an installation from different locations such as the Internet.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (TargetObject ILIKE '%\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\\%' AND (TargetObject ILIKE '%\\Internet' OR TargetObject ILIKE '%\\LocalIntranet' OR TargetObject ILIKE '%\\MyComputer' OR TargetObject ILIKE '%\\TrustedSites' OR TargetObject ILIKE '%\\UntrustedSites') AND Details = 'Enabled')
