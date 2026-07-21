import { buildGitHubAppManifest } from "@mergesignal/github";
import { parseWebEnvironment } from "@mergesignal/config";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  const environment = parseWebEnvironment();
  return Response.json(buildGitHubAppManifest(environment.APP_ORIGIN), {
    headers: { "cache-control": "no-store" }
  });
}
