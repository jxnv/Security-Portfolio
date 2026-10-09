// Title: Google Cloud Kubernetes Secrets Modified or Deleted
// ID: 2f0bae2d-bf20-4465-be86-1311addebaa3
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-08-09
// Tags: attack.credential-access
// Description: Identifies when the Secrets are Modified or Deleted.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((gcp.audit.method_name = "io.k8s.core.v*.secrets.create" or gcp.audit.method_name = "io.k8s.core.v*.secrets.update" or gcp.audit.method_name = "io.k8s.core.v*.secrets.patch" or gcp.audit.method_name = "io.k8s.core.v*.secrets.delete"))
