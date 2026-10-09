// Title: AWS S3 Data Management Tampering
// ID: 78b3756a-7804-4ef7-8555-7b9024a02e2d
// Status: test
// Level: low
// Author: Austin Songer @austinsonger
// Date: 2021-07-24
// Tags: attack.exfiltration, attack.t1537
// Description: Detects when a user tampers with S3 data management in Amazon Web Services.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (eventSource = "s3.amazonaws.com" and (eventName = "PutBucketLogging" or eventName = "PutBucketWebsite" or eventName = "PutEncryptionConfiguration" or eventName = "PutLifecycleConfiguration" or eventName = "PutReplicationConfiguration" or eventName = "ReplicateObject" or eventName = "RestoreObject"))
