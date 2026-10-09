-- Title: Okta FastPass Phishing Detection
-- ID: ee39a9f7-5a79-4b0a-9815-d36b3cf28d3e
-- Status: test
-- Level: high
-- Author: Austin Songer @austinsonger
-- Date: 2023-05-07
-- Tags: attack.initial-access, attack.t1566
-- Description: Detects when Okta FastPass prevents a known phishing site.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (outcome.reason = 'FastPass declined phishing attempt' AND outcome.result = 'FAILURE' AND eventType = 'user.authentication.auth_via_mfa')
