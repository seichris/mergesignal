import { createSign } from "node:crypto";

export const GITHUB_API_VERSION = "2026-03-10";

type FetchImplementation = typeof fetch;

interface TokenEntry {
  token: string;
  expiresAt: number;
}

interface GitHubAppClientOptions {
  appId: string;
  privateKey: string;
  apiBaseUrl?: string;
  fetchImplementation?: FetchImplementation;
  now?: () => Date;
}

interface GraphqlErrorPayload {
  message: string;
  type?: string;
  path?: Array<string | number>;
}

export class GitHubApiError extends Error {
  constructor(
    readonly status: number,
    readonly requestId: string | null,
    readonly retryAfter: string | null,
    message: string,
    readonly rateLimitReset: string | null = null
  ) {
    super(message);
    this.name = "GitHubApiError";
  }
}

export class GitHubGraphqlError extends Error {
  constructor(
    readonly errors: readonly GraphqlErrorPayload[],
    readonly requestId: string | null,
    readonly retryAfter: string | null,
    readonly rateLimitReset: string | null
  ) {
    super(errors.map((error) => error.message).join("; "));
    this.name = "GitHubGraphqlError";
  }

  get retryable(): boolean {
    return this.errors.some((error) =>
      ["RATE_LIMITED", "SERVER_ERROR", "SERVICE_UNAVAILABLE", "TIMEOUT"].includes(
        error.type ?? ""
      )
    );
  }
}

function base64Url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

function repositoryTokenKey(installationId: number, repositoryIds: readonly number[]): string {
  return `${installationId}:${[...repositoryIds].sort((left, right) => left - right).join(",")}`;
}

export class GitHubAppClient {
  readonly appId: string;
  private readonly privateKey: string;
  private readonly apiBaseUrl: string;
  private readonly graphqlUrl: string;
  private readonly fetchImplementation: FetchImplementation;
  private readonly now: () => Date;
  private readonly tokenCache = new Map<string, TokenEntry>();

  constructor(options: GitHubAppClientOptions) {
    this.appId = options.appId;
    this.privateKey = options.privateKey;
    this.apiBaseUrl = (options.apiBaseUrl ?? "https://api.github.com").replace(/\/$/, "");
    this.graphqlUrl = this.apiBaseUrl.endsWith("/api/v3")
      ? `${this.apiBaseUrl.slice(0, -3)}graphql`
      : `${this.apiBaseUrl}/graphql`;
    this.fetchImplementation = options.fetchImplementation ?? fetch;
    this.now = options.now ?? (() => new Date());
  }

  createAppJwt(): string {
    const now = Math.floor(this.now().getTime() / 1_000);
    const unsigned = `${base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${base64Url(
      JSON.stringify({ iat: now - 60, exp: now + 9 * 60, iss: this.appId })
    )}`;
    const signer = createSign("RSA-SHA256");
    signer.update(unsigned);
    return `${unsigned}.${signer.sign(this.privateKey).toString("base64url")}`;
  }

  private async request<T>(
    path: string,
    options: { method?: string; token: string; body?: unknown }
  ): Promise<T> {
    const response = await this.fetchImplementation(`${this.apiBaseUrl}${path}`, {
      method: options.method ?? "GET",
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${options.token}`,
        "content-type": "application/json",
        "user-agent": "MergeSignal/1",
        "x-github-api-version": GITHUB_API_VERSION
      },
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) })
    });
    if (!response.ok) {
      let message = `GitHub API request failed with ${response.status}`;
      try {
        const body = (await response.json()) as { message?: unknown };
        if (typeof body.message === "string") message = body.message;
      } catch {
        // The status and request ID remain sufficient for a typed operational failure.
      }
      throw new GitHubApiError(
        response.status,
        response.headers.get("x-github-request-id"),
        response.headers.get("retry-after"),
        message,
        response.headers.get("x-ratelimit-reset")
      );
    }
    return (await response.json()) as T;
  }

  async getAppIdentity(): Promise<{ id: number; node_id: string; slug: string }> {
    return this.request("/app", { token: this.createAppJwt() });
  }

  async getInstallationToken(
    installationId: number,
    repositoryIds: readonly number[] = []
  ): Promise<string> {
    const key = repositoryTokenKey(installationId, repositoryIds);
    const cached = this.tokenCache.get(key);
    const refreshBoundary = this.now().getTime() + 60_000;
    if (cached !== undefined && cached.expiresAt > refreshBoundary) return cached.token;

    const body = await this.request<{ token: string; expires_at: string }>(
      `/app/installations/${installationId}/access_tokens`,
      {
        method: "POST",
        token: this.createAppJwt(),
        body: repositoryIds.length === 0 ? {} : { repository_ids: repositoryIds }
      }
    );
    const expiresAt = Date.parse(body.expires_at);
    if (!Number.isFinite(expiresAt) || expiresAt <= refreshBoundary) {
      throw new Error("GitHub returned an invalid or immediately expired installation token");
    }
    this.tokenCache.set(key, { token: body.token, expiresAt });
    return body.token;
  }

  async installationRequest<T>(
    installationId: number,
    repositoryId: number,
    path: string,
    options: { method?: string; body?: unknown } = {}
  ): Promise<T> {
    return this.request(path, {
      ...options,
      token: await this.getInstallationToken(installationId, [repositoryId])
    });
  }

  async installationGraphqlRequest<T>(
    installationId: number,
    query: string,
    variables: Readonly<Record<string, unknown>>
  ): Promise<T> {
    const response = await this.fetchImplementation(this.graphqlUrl, {
      method: "POST",
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${await this.getInstallationToken(installationId)}`,
        "content-type": "application/json",
        "user-agent": "MergeSignal/1",
        "x-github-api-version": GITHUB_API_VERSION
      },
      body: JSON.stringify({ query, variables })
    });
    if (!response.ok) {
      let message = `GitHub GraphQL request failed with ${response.status}`;
      try {
        const body = (await response.json()) as { message?: unknown };
        if (typeof body.message === "string") message = body.message;
      } catch {
        // The status and response headers remain sufficient for a typed failure.
      }
      throw new GitHubApiError(
        response.status,
        response.headers.get("x-github-request-id"),
        response.headers.get("retry-after"),
        message,
        response.headers.get("x-ratelimit-reset")
      );
    }
    const body = (await response.json()) as { data?: T; errors?: GraphqlErrorPayload[] };
    if (body.errors !== undefined && body.errors.length > 0) {
      throw new GitHubGraphqlError(
        body.errors,
        response.headers.get("x-github-request-id"),
        response.headers.get("retry-after"),
        response.headers.get("x-ratelimit-reset")
      );
    }
    if (body.data === undefined) throw new Error("GitHub GraphQL response did not contain data");
    return body.data;
  }

  async listInstallationRepositories(installationId: number): Promise<
    Array<{
      id: number;
      nodeId: string;
      fullName: string;
      private: boolean;
      defaultBranch?: string;
    }>
  > {
    const token = await this.getInstallationToken(installationId);
    const repositories: Array<{
      id: number;
      nodeId: string;
      fullName: string;
      private: boolean;
      defaultBranch?: string;
    }> = [];
    for (let page = 1; page <= 100; page += 1) {
      const response = await this.request<{
        repositories: Array<{
          id: number;
          node_id: string;
          full_name: string;
          private: boolean;
          default_branch?: string;
        }>;
      }>(`/installation/repositories?per_page=100&page=${page}`, { token });
      repositories.push(
        ...response.repositories.map((repository) => ({
          id: repository.id,
          nodeId: repository.node_id,
          fullName: repository.full_name,
          private: repository.private,
          ...(repository.default_branch === undefined
            ? {}
            : { defaultBranch: repository.default_branch })
        }))
      );
      if (response.repositories.length < 100) return repositories;
    }
    throw new Error("GitHub installation repository inventory exceeded the pagination limit");
  }
}
