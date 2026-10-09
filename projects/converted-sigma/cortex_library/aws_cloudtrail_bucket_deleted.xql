// Title: AWS Bucket Deleted
// ID: 39c9f26d-6e3b-4dbb-9c7a-4154b0281112
// Status: experimental
// Level: medium
// Author: Ivan Saakov, Nasreddine Bencherchali
// Date: 2025-10-19
// Tags: attack.stealth
// Description: Detects the deletion of S3 buckets in AWS CloudTrail logs.
// Monitoring the deletion of S3 buckets is critical for security and data integrity, as it may indicate potential data loss or unauthorized access attempts.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((eventName = "DeleteBucket") and ((errorCode = null) or (errorCode = "Success")))
