import { metrics, SpanStatusCode, trace, type Attributes } from "@opentelemetry/api";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { HttpInstrumentation } from "@opentelemetry/instrumentation-http";
import { PgInstrumentation } from "@opentelemetry/instrumentation-pg";
import { UndiciInstrumentation } from "@opentelemetry/instrumentation-undici";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { NodeSDK } from "@opentelemetry/sdk-node";
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
  ATTR_DEPLOYMENT_ENVIRONMENT_NAME
} from "@opentelemetry/semantic-conventions";

export interface ObservabilityOptions {
  serviceName: string;
  serviceVersion: string;
  deploymentEnvironment: string;
  deploymentId: string;
  exporterEndpoint?: string;
}

let nodeSdk: NodeSDK | undefined;

function exporterUrl(endpoint: string, signal: "traces" | "metrics"): string {
  return `${endpoint.replace(/\/$/, "")}/v1/${signal}`;
}

export async function startObservability(options: ObservabilityOptions): Promise<void> {
  if (nodeSdk !== undefined || options.exporterEndpoint === undefined) return;

  nodeSdk = new NodeSDK({
    instrumentations: [
      new HttpInstrumentation(),
      new PgInstrumentation(),
      new UndiciInstrumentation()
    ],
    metricReader: new PeriodicExportingMetricReader({
      exporter: new OTLPMetricExporter({
        url: exporterUrl(options.exporterEndpoint, "metrics")
      }),
      exportIntervalMillis: 30_000
    }),
    resource: resourceFromAttributes({
      [ATTR_SERVICE_NAME]: options.serviceName,
      [ATTR_SERVICE_VERSION]: options.serviceVersion,
      [ATTR_DEPLOYMENT_ENVIRONMENT_NAME]: options.deploymentEnvironment,
      "service.instance.id": options.deploymentId
    }),
    traceExporter: new OTLPTraceExporter({
      url: exporterUrl(options.exporterEndpoint, "traces")
    })
  });
  nodeSdk.start();
}

export async function stopObservability(): Promise<void> {
  const sdk = nodeSdk;
  nodeSdk = undefined;
  if (sdk !== undefined) await sdk.shutdown();
}

export async function withSpan<T>(
  name: string,
  attributes: Attributes,
  operation: () => Promise<T>
): Promise<T> {
  const tracer = trace.getTracer("@mergesignal/observability");
  return tracer.startActiveSpan(name, { attributes }, async (span) => {
    try {
      const result = await operation();
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (error) {
      span.recordException(error instanceof Error ? error : new Error("Unknown operation error"));
      span.setStatus({ code: SpanStatusCode.ERROR });
      throw error;
    } finally {
      span.end();
    }
  });
}

const forbiddenLogKey = /(authorization|body|content|cookie|payload|private|secret|token)/i;

export function logEvent(
  severity: "debug" | "info" | "warn" | "error",
  event: string,
  attributes: Record<string, string | number | boolean | null> = {}
): void {
  for (const key of Object.keys(attributes)) {
    if (forbiddenLogKey.test(key)) throw new Error(`Sensitive log attribute is forbidden: ${key}`);
  }
  const spanContext = trace.getActiveSpan()?.spanContext();
  const record = {
    timestamp: new Date().toISOString(),
    severity,
    event,
    ...attributes,
    ...(spanContext === undefined
      ? {}
      : { traceId: spanContext.traceId, spanId: spanContext.spanId })
  };
  process.stdout.write(`${JSON.stringify(record)}\n`);
}

export const foundationMeter = metrics.getMeter("mergesignal.foundation");
