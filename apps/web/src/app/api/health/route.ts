export const dynamic = "force-dynamic";

export function GET(): Response {
  return Response.json(
    {
      status: "ok",
      service: "mergesignal-web",
      deploymentId: process.env.DEPLOYMENT_ID ?? "unknown"
    },
    {
      headers: { "cache-control": "no-store" }
    }
  );
}
