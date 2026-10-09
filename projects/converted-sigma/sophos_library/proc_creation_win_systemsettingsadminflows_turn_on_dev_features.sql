-- Title: Potential Signing Bypass Via Windows Developer Features
-- ID: a383dec4-deec-4e6e-913b-ed9249670848
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-11
-- Tags: attack.stealth
-- Description: Detects when a user enable developer features such as "Developer Mode" or "Application Sideloading". Which allows the user to install untrusted packages.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%TurnOnDeveloperFeatures%') AND ((Image ILIKE '%\\SystemSettingsAdminFlows.exe') OR (OriginalFileName = 'SystemSettingsAdminFlows.EXE')) AND ((CommandLine ILIKE '%DeveloperUnlock%' OR CommandLine ILIKE '%EnableSideloading%')))
