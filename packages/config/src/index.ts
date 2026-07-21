import { z } from "zod";

const environmentName = z.enum(["development", "test", "staging", "production"]);

const nonEmptyOptional = z.preprocess(
  (value) => (typeof value === "string" && value.trim() === "" ? undefined : value),
  z.string().min(1).optional()
);

const baseSchema = z.object({
  MERGESIGNAL_ENV: environmentName.default("development"),
  DEPLOYMENT_ID: z.string().min(1),
  OTEL_EXPORTER_OTLP_ENDPOINT: nonEmptyOptional
});

const databaseSchema = z.object({
  DATABASE_URL: z.string().url().refine((value) => value.startsWith("postgres"), {
    message: "DATABASE_URL must use PostgreSQL"
  })
});

const githubApiBaseUrl = z.string().url().default("https://api.github.com");
const appOrigin = z.string().url().transform((value) => value.replace(/\/$/, ""));
const githubPrivateKey = z.string().min(1).refine(
  (value) => {
    try {
      return Buffer.from(value, "base64").toString("utf8").includes("PRIVATE KEY-----");
    } catch {
      return false;
    }
  },
  { message: "GITHUB_APP_PRIVATE_KEY_BASE64 must contain a base64-encoded PEM private key" }
);

const temporalSchema = z
  .object({
    MERGESIGNAL_ENV: environmentName.default("development"),
    TEMPORAL_ADDRESS: z.string().min(1),
    TEMPORAL_NAMESPACE: z.string().min(1),
    TEMPORAL_TASK_QUEUE: z.string().min(1),
    TEMPORAL_TLS_ENABLED: z
      .enum(["true", "false"])
      .default("false")
      .transform((value) => value === "true"),
    TEMPORAL_API_KEY: nonEmptyOptional,
    TEMPORAL_TLS_CERT: nonEmptyOptional,
    TEMPORAL_TLS_KEY: nonEmptyOptional,
    TEMPORAL_WORKER_VERSIONING_ENABLED: z
      .enum(["true", "false"])
      .default("false")
      .transform((value) => value === "true"),
    TEMPORAL_DEPLOYMENT_NAME: z.string().min(1).default("mergesignal-worker"),
    WORKER_BUILD_ID: z.string().min(1),
    WORKER_HEALTH_PORT: z.coerce.number().int().min(1).max(65_535).default(8080),
    GITHUB_APP_ID: z.string().regex(/^[1-9][0-9]*$/),
    GITHUB_APP_PRIVATE_KEY_BASE64: githubPrivateKey,
    GITHUB_API_BASE_URL: githubApiBaseUrl,
    GITHUB_VERIFY_APP_IDENTITY: z
      .enum(["true", "false"])
      .default("false")
      .transform((value) => value === "true"),
    APP_ORIGIN: appOrigin
  })
  .superRefine((value, context) => {
    const hasCertificate = value.TEMPORAL_TLS_CERT !== undefined;
    const hasKey = value.TEMPORAL_TLS_KEY !== undefined;
    if (hasCertificate !== hasKey) {
      context.addIssue({
        code: "custom",
        message: "TEMPORAL_TLS_CERT and TEMPORAL_TLS_KEY must be supplied together"
      });
    }
    if (value.TEMPORAL_API_KEY !== undefined && hasCertificate) {
      context.addIssue({
        code: "custom",
        message: "Use either a Temporal API key or mTLS client credentials, not both"
      });
    }
    if (hasCertificate && !value.TEMPORAL_TLS_ENABLED) {
      context.addIssue({
        code: "custom",
        message: "Temporal mTLS credentials require TEMPORAL_TLS_ENABLED=true"
      });
    }
    if (value.MERGESIGNAL_ENV === "production" && value.TEMPORAL_ADDRESS.startsWith("127.0.0.1")) {
      context.addIssue({
        code: "custom",
        message: "Production cannot use a loopback Temporal address"
      });
    }
  });

const workerSchema = baseSchema
  .and(databaseSchema)
  .and(temporalSchema)
  .superRefine((value, context) => {
    if (value.MERGESIGNAL_ENV === "production" && !value.TEMPORAL_WORKER_VERSIONING_ENABLED) {
      context.addIssue({
        code: "custom",
        message: "Production workers must enable Temporal Worker Deployment Versioning"
      });
    }
    if (value.MERGESIGNAL_ENV === "production" && !value.TEMPORAL_TLS_ENABLED) {
      context.addIssue({
        code: "custom",
        message: "Production workers must enable Temporal TLS"
      });
    }
    if (value.MERGESIGNAL_ENV === "production" && !value.GITHUB_VERIFY_APP_IDENTITY) {
      context.addIssue({
        code: "custom",
        message: "Production workers must verify the authenticated GitHub App identity"
      });
    }
    if (value.MERGESIGNAL_ENV === "production" && !value.APP_ORIGIN.startsWith("https://")) {
      context.addIssue({ code: "custom", message: "Production APP_ORIGIN must use HTTPS" });
    }
  });

const webSchema = baseSchema.and(databaseSchema).and(
  z.object({
    INTERNAL_INGRESS_TOKEN: z.string().min(32),
    GITHUB_APP_ID: z.string().regex(/^[1-9][0-9]*$/),
    GITHUB_APP_SLUG: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
    GITHUB_WEBHOOK_SECRET: z.string().min(32),
    APP_ORIGIN: appOrigin
  })
).superRefine((value, context) => {
  if (value.MERGESIGNAL_ENV === "production" && !value.APP_ORIGIN.startsWith("https://")) {
    context.addIssue({ code: "custom", message: "Production APP_ORIGIN must use HTTPS" });
  }
});

export type WorkerEnvironment = z.infer<typeof workerSchema>;
export type WebEnvironment = z.infer<typeof webSchema>;
export type MigrationEnvironment = z.infer<typeof databaseSchema>;

export function parseWorkerEnvironment(
  environment: NodeJS.ProcessEnv = process.env
): WorkerEnvironment {
  return workerSchema.parse(environment);
}

export function parseWebEnvironment(
  environment: NodeJS.ProcessEnv = process.env
): WebEnvironment {
  return webSchema.parse(environment);
}

export function parseMigrationEnvironment(
  environment: NodeJS.ProcessEnv = process.env
): MigrationEnvironment {
  return databaseSchema.parse(environment);
}
