output "temporal_namespace_id" {
  description = "Temporal Cloud namespace identifier."
  value       = temporalcloud_namespace.workflows.id
}

output "temporal_namespace_endpoints" {
  description = "Temporal Cloud namespace endpoints consumed by Coolify."
  value       = temporalcloud_namespace.workflows.endpoints
}

output "vercel_project_id" {
  description = "Vercel control-plane project identifier."
  value       = vercel_project.control_plane.id
}
