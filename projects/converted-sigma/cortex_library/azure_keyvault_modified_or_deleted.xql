// Title: Azure Key Vault Modified or Deleted
// ID: 459a2970-bb84-4e6a-a32e-ff0fbd99448d
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-08-16
// Tags: attack.impact, attack.credential-access, attack.t1552, attack.t1552.001
// Description: Identifies when a key vault is modified or deleted.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((operationName = "MICROSOFT.KEYVAULT/VAULTS/WRITE" or operationName = "MICROSOFT.KEYVAULT/VAULTS/DELETE" or operationName = "MICROSOFT.KEYVAULT/VAULTS/DEPLOY/ACTION" or operationName = "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE"))
