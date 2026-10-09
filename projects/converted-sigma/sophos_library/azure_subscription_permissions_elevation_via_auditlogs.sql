-- Title: Azure Subscription Permission Elevation Via AuditLogs
-- ID: ca9bf243-465e-494a-9e54-bf9fc239057d
-- Status: test
-- Level: high
-- Author: Austin Songer @austinsonger
-- Date: 2021-11-26
-- Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.stealth, attack.t1078
-- Description: Detects when a user has been elevated to manage all Azure Subscriptions.
-- This change should be investigated immediately if it isn't planned.
-- This setting could allow an attacker access to Azure subscriptions in your environment.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Category = 'AzureRBACRoleManagementElevateAccess' AND ActivityDisplayName = 'User has elevated their access to User Access Administrator for their Azure Resources')
