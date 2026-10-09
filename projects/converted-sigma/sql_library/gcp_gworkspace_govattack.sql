-- Title: Google Workspace Government Attack Warning
-- ID: eafe6f2b-cfec-4612-aec2-49563c33a087
-- Status: experimental
-- Level: medium
-- Author: Tom Kluter
-- Date: 2026-04-28
-- Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.impact, attack.stealth, attack.t1078
-- Description: Detects a login attempt in Google Workspace flagged as a potential attack by a government-backed threat actor
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (protoPayload.serviceName = 'login.googleapis.com' AND protoPayload.metadata.event.eventName = 'gov_attack_warning')
