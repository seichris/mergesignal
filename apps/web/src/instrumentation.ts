export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { startObservability } = await import("@mergesignal/observability");
  await startObservability({
    serviceName: "mergesignal-web",
    serviceVersion: process.env.VERCEL_GIT_COMMIT_SHA ?? "development",
    deploymentEnvironment: process.env.MERGESIGNAL_ENV ?? "development",
    deploymentId: process.env.DEPLOYMENT_ID ?? "unknown",
    ...(process.env.OTEL_EXPORTER_OTLP_ENDPOINT === undefined
      ? {}
      : { exporterEndpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT })
  });
}
