variable "environment" {
  description = "MergeSignal deployment environment."
  type        = string

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "environment must be development, staging, or production"
  }
}

variable "github_repository" {
  description = "GitHub repository connected to the Vercel project, in owner/name form."
  type        = string
}

variable "temporal_region" {
  description = "Temporal Cloud region, including its cloud-provider prefix."
  type        = string
}

variable "vercel_team_id" {
  description = "Vercel Kontext team ID."
  type        = string
}

variable "temporal_retention_days" {
  description = "Workflow history retention for replay and incident investigation."
  type        = number
  default     = 30

  validation {
    condition     = var.temporal_retention_days >= 7 && var.temporal_retention_days <= 90
    error_message = "Temporal retention must be between 7 and 90 days"
  }
}
