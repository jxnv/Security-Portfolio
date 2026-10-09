-- Title: Rare Subscription-level Operations In Azure
-- ID: c1182e02-49a3-481c-b3de-0fadc4091488
-- Status: test
-- Level: medium
-- Author: sawwinnnaung
-- Date: 2020-05-07
-- Tags: attack.t1003, attack.credential-access
-- Description: Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ("Microsoft.DocumentDB/databaseAccounts/listKeys/action" OR "Microsoft.Maps/accounts/listKeys/action" OR "Microsoft.Media/mediaservices/listKeys/action" OR "Microsoft.CognitiveServices/accounts/listKeys/action" OR "Microsoft.Storage/storageAccounts/listKeys/action" OR "Microsoft.Compute/snapshots/write" OR "Microsoft.Network/networkSecurityGroups/write")
