// Title: Azure Kubernetes Service Account Modified or Deleted
// ID: 12d027c3-b48c-4d9d-8bb6-a732200034b2
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-08-07
// Tags: attack.impact, attack.t1531, attack.t1485, attack.t1496, attack.t1489
// Description: Identifies when a service account is modified or deleted.
// Converted by: Sigma Universal SIEM/EDR CLI

((operationName: "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/SERVICEACCOUNTS/WRITE" OR operationName: "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/SERVICEACCOUNTS/DELETE" OR operationName: "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/SERVICEACCOUNTS/IMPERSONATE/ACTION"))
