-- Title: Azure Kubernetes Cluster Created or Deleted
-- ID: 9541f321-7cba-4b43-80fc-fbd1fb922808
-- Status: test
-- Level: low
-- Author: Austin Songer @austinsonger
-- Date: 2021-08-07
-- Tags: attack.impact, attack.t1485, attack.t1496, attack.t1489
-- Description: Detects when a Azure Kubernetes Cluster is created or deleted.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((operationName = 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/WRITE' OR operationName = 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/DELETE'))
