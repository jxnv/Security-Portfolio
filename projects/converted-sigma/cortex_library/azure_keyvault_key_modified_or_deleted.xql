// Title: Azure Keyvault Key Modified or Deleted
// ID: 80eeab92-0979-4152-942d-96749e11df40
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-08-16
// Tags: attack.impact, attack.credential-access, attack.t1552, attack.t1552.001
// Description: Identifies when a Keyvault Key is modified or deleted in Azure.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((operationName = "MICROSOFT.KEYVAULT/VAULTS/KEYS/UPDATE/ACTION" or operationName = "MICROSOFT.KEYVAULT/VAULTS/KEYS/CREATE" or operationName = "MICROSOFT.KEYVAULT/VAULTS/KEYS/CREATE/ACTION" or operationName = "MICROSOFT.KEYVAULT/VAULTS/KEYS/IMPORT/ACTION" or operationName = "MICROSOFT.KEYVAULT/VAULTS/KEYS/RECOVER/ACTION" or operationName = "MICROSOFT.KEYVAULT/VAULTS/KEYS/RESTORE/ACTION" or operationName = "MICROSOFT.KEYVAULT/VAULTS/KEYS/DELETE" or operationName = "MICROSOFT.KEYVAULT/VAULTS/KEYS/BACKUP/ACTION" or operationName = "MICROSOFT.KEYVAULT/VAULTS/KEYS/PURGE/ACTION"))
