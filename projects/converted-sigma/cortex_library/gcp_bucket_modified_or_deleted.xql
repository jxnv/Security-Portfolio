// Title: Google Cloud Storage Buckets Modified or Deleted
// ID: 4d9f2ee2-c903-48ab-b9c1-8c0f474913d0
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-08-14
// Tags: attack.impact
// Description: Detects when storage bucket is modified or deleted in Google Cloud.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((gcp.audit.method_name = "storage.buckets.delete" or gcp.audit.method_name = "storage.buckets.insert" or gcp.audit.method_name = "storage.buckets.update" or gcp.audit.method_name = "storage.buckets.patch"))
