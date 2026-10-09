-- Title: Google Workspace MFA Disabled
-- ID: 780601d1-6376-4f2a-884e-b8d45599f78c
-- Status: test
-- Level: medium
-- Author: Austin Songer
-- Date: 2021-08-26
-- Tags: attack.impact
-- Description: Detects when multi-factor authentication (MFA) is disabled.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((eventService = 'admin.googleapis.com' AND (eventName = 'ENFORCE_STRONG_AUTHENTICATION' OR eventName = 'ALLOW_STRONG_AUTHENTICATION')) AND (new_value = 'false'))
