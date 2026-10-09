-- Title: Activity Performed by Terminated User
-- ID: 2e669ed8-742e-4fe5-b3c4-5a59b486c2ee
-- Status: test
-- Level: medium
-- Author: Austin Songer @austinsonger
-- Date: 2021-08-23
-- Tags: attack.impact
-- Description: Detects when a Microsoft Cloud App Security reported for users whose account were terminated in Azure AD, but still perform activities in other platforms such as AWS or Salesforce.
-- This is especially relevant for users who use another account to manage resources, since these accounts are often not terminated when a user leaves the company.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (eventSource = 'SecurityComplianceCenter' AND eventName = 'Activity performed by terminated user' AND status = 'success')
