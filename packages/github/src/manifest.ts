export function buildGitHubAppManifest(appOrigin: string) {
  const origin = appOrigin.replace(/\/$/, "");
  return {
    name: "MergeSignal",
    url: origin,
    description: "Contributor reputation and evidence context for pull-request maintainers.",
    hook_attributes: {
      url: `${origin}/api/github/webhooks`,
      active: true
    },
    redirect_url: `${origin}/api/github/manifest/callback`,
    setup_url: `${origin}/install/setup`,
    callback_urls: [`${origin}/api/auth/github/callback`],
    public: true,
    request_oauth_on_install: false,
    setup_on_update: true,
    default_permissions: {
      checks: "write",
      contents: "read",
      metadata: "read",
      pull_requests: "write"
    },
    default_events: ["check_run", "installation", "installation_repositories", "pull_request"]
  } as const;
}
