terraform {
  required_version = "~> 1.14"

  required_providers {
    temporalcloud = {
      source = "temporalio/temporalcloud"
    }
    vercel = {
      source = "vercel/vercel"
    }
  }
}
