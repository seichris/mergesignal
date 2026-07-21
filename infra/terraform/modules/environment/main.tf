resource "vercel_project" "control_plane" {
  name                                              = "mergesignal-${var.environment}"
  team_id                                           = var.vercel_team_id
  framework                                         = "nextjs"
  root_directory                                    = "apps/web"
  node_version                                      = "22.x"
  build_command                                     = "cd ../.. && pnpm turbo run build --filter=@mergesignal/web..."
  install_command                                   = "cd ../.. && corepack enable && pnpm install --frozen-lockfile"
  enable_affected_projects_deployments              = true
  automatically_expose_system_environment_variables = true
  git_fork_protection                               = true
  protected_sourcemaps                              = true
  skew_protection                                   = "12 hours"

  git_repository = {
    type = "github"
    repo = var.github_repository
  }
}

resource "temporalcloud_namespace" "workflows" {
  name           = "mergesignal-${var.environment}"
  regions        = [var.temporal_region]
  api_key_auth   = true
  retention_days = var.temporal_retention_days

  capacity = {
    mode = "on_demand"
  }

  namespace_lifecycle = {
    enable_delete_protection = var.environment != "development"
  }
}
