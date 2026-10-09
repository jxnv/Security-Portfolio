-- Title: Enable Local Manifest Installation With Winget
-- ID: fa277e82-9b78-42dd-b05c-05555c7b6015
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-17
-- Tags: attack.persistence, attack.stealth
-- Description: Detects changes to the AppInstaller (winget) policy. Specifically the activation of the local manifest installation, which allows a user to install new packages via custom manifests.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (TargetObject="*\\AppInstaller\\EnableLocalManifestFiles" AND Details = 'DWORD (0x00000001)')
