// Title: Azure Active Directory Hybrid Health AD FS New Server
// ID: 288a39fc-4914-4831-9ada-270e9dc12cb4
// Status: test
// Level: medium
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
// Date: 2021-08-26
// Tags: attack.defense-impairment, attack.t1578
// Description: This detection uses azureactivity logs (Administrative category) to identify the creation or update of a server instance in an Azure AD Hybrid health AD FS service.
// A threat actor can create a new AD Health ADFS service and create a fake server instance to spoof AD FS signing logs. There is no need to compromise an on-prem AD FS server.
// This can be done programmatically via HTTP requests to Azure.
// Converted by: Sigma Universal SIEM/EDR CLI

(CategoryValue == "Administrative" AND ResourceProviderValue == "Microsoft.ADHybridHealthService" AND ResourceId contains "AdFederationService" AND OperationNameValue == "Microsoft.ADHybridHealthService/services/servicemembers/action")
