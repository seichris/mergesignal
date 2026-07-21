terraform {
  required_version = "~> 1.14"

  required_providers {
    temporalcloud = {
      source  = "temporalio/temporalcloud"
      version = "1.6.0"
    }
    vercel = {
      source  = "vercel/vercel"
      version = "5.4.1"
    }
  }
}

provider "temporalcloud" {}
provider "vercel" {}

module "environment" {
  source = "../../modules/environment"

  environment             = "production"
  github_repository       = var.github_repository
  temporal_region         = var.temporal_region
  temporal_retention_days = 60
  vercel_team_id          = var.vercel_team_id
}

variable "github_repository" {
  type = string
}

variable "temporal_region" {
  type = string
}

variable "vercel_team_id" {
  type = string
}
