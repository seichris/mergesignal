import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { resolve } from "node:path";

import { Client } from "@temporalio/client";
import { NativeConnection, Worker } from "@temporalio/worker";

import {
  acceptGitHubDelivery,
  applyGitHubDelivery,
  claimGitHubPublication,
  completeGitHubPublication,
  createDatabase,
  reconcileInstallationRepositories,
  recordGitHubOutputObservation,
  withTenantTransaction
} from "../../packages/database/dist/index.js";
import { migrateDatabase } from "../../packages/database/dist/migrations.js";
import {
  markerFor,
  reconcilePullRequestOutput
} from "../../packages/github-output/dist/index.js";
import { createActivities } from "../../apps/worker/dist/activities.js";
import { runOutboxRelay } from "../../apps/worker/dist/outbox-relay.js";

const databaseUrl = process.env.DATABASE_URL;
if (databaseUrl === undefined) throw new Error("DATABASE_URL is required for Phase 2 integration");

const appId = 9001;
const installationId = Number(`${Date.now()}`.slice(-9));
const repositoryId = installationId + 1;
const pullRequestId = installationId + 2;
const repository = {
  id: repositoryId,
  nodeId: `R_phase2_${installationId}`,
  fullName: `mergesignal-fixture-${installationId}/repository`,
  private: false,
  defaultBranch: "main"
};

function installationEnvelope(action = "created") {
  return {
    event: "installation",
    action,
    installation: {
      id: installationId,
      accountNodeId: `O_phase2_${installationId}`,
      accountLogin: `mergesignal-fixture-${installationId}`,
      accountType: "Organization",
      permissions: { checks: "write", contents: "read", metadata: "read", pull_requests: "write" },
      events: ["check_run", "installation", "installation_repositories", "pull_request"],
      repositorySelection: "selected"
    },
    repositories: [repository]
  };
}

function pullRequestEnvelope(action, headSha, updatedAt) {
  return {
    event: "pull_request",
    action,
    installation: installationEnvelope().installation,
    repository,
    pullRequest: {
      id: pullRequestId,
      nodeId: `PR_phase2_${installationId}`,
      number: 17,
      state: "open",
      draft: false,
      updatedAt,
      headSha,
      baseSha: "0".repeat(40),
      authorNodeId: "U_phase2_contributor",
      authorLogin: "phase2-contributor",
      authorType: "User"
    }
  };
}

function checkRunEnvelope(headSha) {
  return {
    event: "check_run",
    action: "rerequested",
    installation: installationEnvelope().installation,
    repository,
    checkRun: { id: installationId + 3, headSha, name: "MergeSignal", appId }
  };
}

async function accept(database, envelope, deliveryId = randomUUID()) {
  const body = JSON.stringify(envelope);
  const result = await acceptGitHubDelivery(database, {
    deliveryId,
    bodyDigest: createHash("sha256").update(body).digest("hex"),
    envelope
  });
  return { deliveryId, result };
}

class FakeGitHubProvider {
  head;
  comments = [];
  checks = [];
  changeHeadAfterCommentTo = null;

  constructor(head) {
    this.head = head;
  }
  async getPullRequestHead() {
    return this.head;
  }
  async listPullRequestComments() {
    return this.comments;
  }
  async getComment(_target, commentId) {
    return this.comments.find((comment) => comment.id === commentId) ?? null;
  }
  async createComment(target, body) {
    const comment = { id: 1000 + this.comments.length, body, performedViaGitHubAppId: target.appId };
    this.comments.push(comment);
    if (this.changeHeadAfterCommentTo !== null) this.head = this.changeHeadAfterCommentTo;
    return comment;
  }
  async updateComment(_target, commentId, body) {
    const comment = this.comments.find((candidate) => candidate.id === commentId);
    if (comment === undefined) throw new Error("canonical comment disappeared");
    comment.body = body;
    if (this.changeHeadAfterCommentTo !== null) this.head = this.changeHeadAfterCommentTo;
    return comment;
  }
  async createCheckRun(target) {
    const check = { id: 2000 + this.checks.length, headSha: target.headSha, conclusion: null };
    this.checks.push(check);
    return check;
  }
  async completeCheckRun(_target, checkRunId, input) {
    const check = this.checks.find((candidate) => candidate.id === checkRunId);
    if (check === undefined) throw new Error("check run disappeared");
    check.conclusion = input.conclusion;
    return check;
  }
}

class FakeGitHubClient {
  graphqlCalls = 0;

  async listInstallationRepositories() {
    return [repository];
  }

  async installationGraphqlRequest() {
    this.graphqlCalls += 1;
    return {
      node: {
        __typename: "User",
        id: "U_phase2_contributor",
        login: "phase2-contributor",
        createdAt: "2020-01-01T00:00:00.000Z",
        contributionsCollection: {
          restrictedContributionsCount: 7,
          totalCommitContributions: 120,
          totalIssueContributions: 8,
          totalPullRequestContributions: 12,
          totalPullRequestReviewContributions: 15,
          totalRepositoriesWithContributedCommits: 1,
          contributionCalendar: {
            weeks: [
              {
                firstDay: "2026-07-19",
                contributionDays: [{ date: "2026-07-21", contributionCount: 4 }]
              }
            ]
          },
          commitContributionsByRepository: [
            {
              repository: {
                nameWithOwner: "community/project",
                isPrivate: false,
                owner: { login: "community" }
              },
              contributions: {
                totalCount: 1,
                nodes: [
                  { occurredAt: "2026-07-21T00:00:00.000Z", isRestricted: false }
                ]
              }
            }
          ],
          pullRequestContributions: {
            totalCount: 2,
            nodes: [
              {
                occurredAt: "2026-07-20T00:00:00.000Z",
                pullRequest: {
                  state: "MERGED",
                  merged: true,
                  mergedAt: "2026-07-21T00:00:00.000Z",
                  repository: {
                    nameWithOwner: "community/project",
                    isPrivate: false,
                    owner: { login: "community" }
                  }
                }
              },
              {
                occurredAt: "2026-07-18T00:00:00.000Z",
                pullRequest: {
                  state: "CLOSED",
                  merged: false,
                  mergedAt: null,
                  repository: {
                    nameWithOwner: "another/project",
                    isPrivate: false,
                    owner: { login: "another" }
                  }
                }
              }
            ],
            pageInfo: { hasNextPage: false, endCursor: null }
          }
        }
      }
    };
  }
}

const fakeGitHubClient = new FakeGitHubClient();

async function publish(database, provider, command) {
  const activities = createActivities(database, {
    client: fakeGitHubClient,
    outputProvider: provider,
    appId,
    appOrigin: "https://mergesignal.example.test"
  });
  await activities.assessGitHubPublication(command);
  const claim = await claimGitHubPublication(database, command);
  const target = {
    installationId: claim.installationId,
    appId,
    repositoryId: claim.repositoryId,
    repositoryNodeId: claim.repositoryNodeId,
    owner: claim.owner,
    repository: claim.repository,
    pullRequestNodeId: claim.pullRequestNodeId,
    pullRequestNumber: claim.pullRequestNumber,
    headSha: claim.headSha,
    generation: claim.generation,
    canonicalCommentId: claim.canonicalCommentId,
    checkRunId: claim.checkRunId,
    assessment: claim.assessment
  };
  const completion = await reconcilePullRequestOutput(provider, target, (observation) =>
    recordGitHubOutputObservation(database, {
      tenantId: claim.tenantId,
      publicationId: claim.publicationId,
      ...observation,
      appId,
      marker: markerFor(target)
    })
  );
  return completeGitHubPublication(database, {
    tenantId: claim.tenantId,
    publicationId: claim.publicationId,
    leaseToken: claim.leaseToken,
    completion
  });
}

async function waitForDurablePublication(database, tenantId, pullRequestNodeId) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const state = await withTenantTransaction(database, tenantId, async (transaction) => {
      const cursor = await transaction
        .selectFrom("app.pr_output_cursors")
        .innerJoin("app.pull_requests", "app.pull_requests.id", "app.pr_output_cursors.pull_request_id")
        .select(["app.pr_output_cursors.state", "app.pr_output_cursors.head_sha"])
        .where("app.pull_requests.pull_request_node_id", "=", pullRequestNodeId)
        .executeTakeFirst();
      const workflow = await transaction
        .selectFrom("app.workflow_runs")
        .select("state")
        .where("source_delivery_id", "=", durableDeliveryId)
        .executeTakeFirst();
      return { cursor, workflow };
    });
    if (state.cursor?.state === "published" && state.workflow?.state === "completed") return state;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
  throw new Error("Durable GitHub publication did not complete before the deadline");
}

let durableDeliveryId = "";

await migrateDatabase(databaseUrl);
const database = createDatabase(databaseUrl, {
  applicationName: "mergesignal-phase2-integration",
  maximumPoolSize: 10
});

try {
  const createdDeliveryId = randomUUID();
  const created = await accept(database, installationEnvelope(), createdDeliveryId);
  const duplicate = await accept(database, installationEnvelope(), createdDeliveryId);
  assert.equal(created.result.accepted, true);
  assert.equal(duplicate.result.accepted, false);
  assert.equal(created.result.deliveryRecordId, duplicate.result.deliveryRecordId);
  await assert.rejects(
    acceptGitHubDelivery(database, {
      deliveryId: createdDeliveryId,
      bodyDigest: "f".repeat(64),
      envelope: installationEnvelope()
    }),
    /changed digest/
  );

  const installationApplied = await applyGitHubDelivery(database, {
    tenantId: created.result.tenantId,
    deliveryId: createdDeliveryId,
    expectedAppId: appId
  });
  assert.equal(installationApplied.reconcileInstallation, true);
  assert.equal(installationApplied.publication, null);
  await reconcileInstallationRepositories(database, {
    tenantId: created.result.tenantId,
    installationId,
    repositories: [repository]
  });

  const headA = "a".repeat(40);
  const headB = "b".repeat(40);
  const headC = "c".repeat(40);
  const opened = await accept(
    database,
    pullRequestEnvelope("opened", headA, "2026-07-21T10:00:00Z")
  );
  const middle = await accept(
    database,
    pullRequestEnvelope("synchronize", headB, "2026-07-21T10:01:00Z")
  );
  const newest = await accept(
    database,
    pullRequestEnvelope("synchronize", headC, "2026-07-21T10:02:00Z")
  );

  const firstPublication = await applyGitHubDelivery(database, {
    tenantId: created.result.tenantId,
    deliveryId: opened.deliveryId,
    expectedAppId: appId
  });
  assert.notEqual(firstPublication.publication, null);
  const newestPublication = await applyGitHubDelivery(database, {
    tenantId: created.result.tenantId,
    deliveryId: newest.deliveryId,
    expectedAppId: appId
  });
  assert.equal(newestPublication.publication?.headSha, headC);
  const staleApplication = await applyGitHubDelivery(database, {
    tenantId: created.result.tenantId,
    deliveryId: middle.deliveryId,
    expectedAppId: appId
  });
  assert.equal(staleApplication.publication, null);

  const repeated = await Promise.all([
    applyGitHubDelivery(database, {
      tenantId: created.result.tenantId,
      deliveryId: newest.deliveryId,
      expectedAppId: appId
    }),
    applyGitHubDelivery(database, {
      tenantId: created.result.tenantId,
      deliveryId: newest.deliveryId,
      expectedAppId: appId
    })
  ]);
  assert.equal(repeated[0].publication?.publicationId, newestPublication.publication?.publicationId);
  assert.equal(repeated[1].publication?.publicationId, newestPublication.publication?.publicationId);

  const provider = new FakeGitHubProvider(headC);
  assert.equal(await publish(database, provider, newestPublication.publication), null);
  assert.equal(await publish(database, provider, newestPublication.publication), null);
  assert.equal(provider.comments.length, 1);
  assert.equal(provider.checks.length, 1);
  assert.match(provider.comments[0].body, /\d+\/100/);
  assert.match(provider.comments[0].body, /External pull requests/);

  const rerun = await accept(database, checkRunEnvelope(headC));
  const rerunApplied = await applyGitHubDelivery(database, {
    tenantId: created.result.tenantId,
    deliveryId: rerun.deliveryId,
    expectedAppId: appId
  });
  assert.equal(rerunApplied.publication?.generation, 3);
  await publish(database, provider, rerunApplied.publication);
  assert.equal(provider.comments.length, 1);
  assert.equal(provider.checks.length, 2);

  const headD = "d".repeat(40);
  const headE = "e".repeat(40);
  const changed = await accept(
    database,
    pullRequestEnvelope("synchronize", headD, "2026-07-21T10:03:00Z")
  );
  const changedApplied = await applyGitHubDelivery(database, {
    tenantId: created.result.tenantId,
    deliveryId: changed.deliveryId,
    expectedAppId: appId
  });
  provider.head = headD;
  provider.changeHeadAfterCommentTo = headE;
  const repair = await publish(database, provider, changedApplied.publication);
  assert.equal(repair?.headSha, headE);
  provider.changeHeadAfterCommentTo = null;
  await publish(database, provider, repair);

  const finalState = await withTenantTransaction(database, created.result.tenantId, async (transaction) => {
    const cursor = await transaction
      .selectFrom("app.pr_output_cursors")
      .selectAll()
      .executeTakeFirstOrThrow();
    const publications = await transaction
      .selectFrom("app.github_publications")
      .select(["id", "generation", "head_sha", "state", "comment_id", "check_run_id"])
      .orderBy("generation")
      .execute();
    const transitions = await transaction
      .selectFrom("app.github_publication_transitions")
      .select(["publication_id", "revision"])
      .orderBy("publication_id")
      .orderBy("revision")
      .execute();
    const observations = await transaction
      .selectFrom("app.github_output_observations")
      .select(({ fn }) => fn.countAll().as("count"))
      .executeTakeFirstOrThrow();
    const assessments = await transaction
      .selectFrom("app.pr_reputation_assessments")
      .select(({ fn }) => fn.countAll().as("count"))
      .executeTakeFirstOrThrow();
    const snapshots = await transaction
      .selectFrom("app.contributor_history_snapshots")
      .select(({ fn }) => fn.countAll().as("count"))
      .executeTakeFirstOrThrow();
    return { cursor, publications, transitions, observations, assessments, snapshots };
  });

  assert.equal(finalState.cursor.head_sha, headE);
  assert.equal(finalState.cursor.generation, 5);
  assert.equal(finalState.cursor.state, "published");
  assert.equal(Number(finalState.cursor.canonical_comment_id), provider.comments[0].id);
  assert.equal(Number(finalState.cursor.current_check_run_id), provider.checks.at(-1).id);
  assert.equal(provider.comments.length, 1);
  assert.equal(provider.checks.filter((check) => check.headSha === headE).length, 1);
  assert.ok(Number(finalState.observations.count) >= 15);
  assert.equal(Number(finalState.assessments.count), 4);
  assert.equal(Number(finalState.snapshots.count), 1);
  assert.equal(fakeGitHubClient.graphqlCalls, 2);
  for (const publication of finalState.publications) {
    const revisions = finalState.transitions
      .filter((transition) => transition.publication_id === publication.id)
      .map((transition) => transition.revision);
    assert.deepEqual(revisions, Array.from({ length: revisions.length }, (_, index) => index + 1));
  }

  const botHead = "7".repeat(40);
  const botEnvelope = pullRequestEnvelope("opened", botHead, "2026-07-21T10:03:30Z");
  botEnvelope.pullRequest.id += 200;
  botEnvelope.pullRequest.number = 19;
  botEnvelope.pullRequest.nodeId = `PR_phase2_bot_${installationId}`;
  botEnvelope.pullRequest.authorNodeId = "B_phase2_bot";
  botEnvelope.pullRequest.authorLogin = "phase2-bot";
  botEnvelope.pullRequest.authorType = "Bot";
  const bot = await accept(database, botEnvelope);
  const botApplied = await applyGitHubDelivery(database, {
    tenantId: created.result.tenantId,
    deliveryId: bot.deliveryId,
    expectedAppId: appId
  });
  const botProvider = new FakeGitHubProvider(botHead);
  await publish(database, botProvider, botApplied.publication);
  assert.doesNotMatch(botProvider.comments[0].body, /\d+\/100/);
  assert.match(botProvider.comments[0].body, /did not calculate a reputation score/);

  const unavailableHead = "8".repeat(40);
  const unavailableEnvelope = pullRequestEnvelope(
    "opened",
    unavailableHead,
    "2026-07-21T10:03:45Z"
  );
  unavailableEnvelope.pullRequest.id += 300;
  unavailableEnvelope.pullRequest.number = 20;
  unavailableEnvelope.pullRequest.nodeId = `PR_phase2_unavailable_${installationId}`;
  unavailableEnvelope.pullRequest.authorNodeId = "U_phase2_unavailable";
  unavailableEnvelope.pullRequest.authorLogin = "unavailable-contributor";
  const unavailable = await accept(database, unavailableEnvelope);
  const unavailableApplied = await applyGitHubDelivery(database, {
    tenantId: created.result.tenantId,
    deliveryId: unavailable.deliveryId,
    expectedAppId: appId
  });
  const unavailableProvider = new FakeGitHubProvider(unavailableHead);
  await publish(database, unavailableProvider, unavailableApplied.publication);
  assert.doesNotMatch(unavailableProvider.comments[0].body, /\d+\/100/);
  assert.match(unavailableProvider.comments[0].body, /No zero score was substituted/);

  const exceptionalStates = await withTenantTransaction(
    database,
    created.result.tenantId,
    (transaction) => transaction
      .selectFrom("app.pr_reputation_assessments")
      .select(["status", "reason"])
      .where("publication_id", "in", [
        botApplied.publication.publicationId,
        unavailableApplied.publication.publicationId
      ])
      .orderBy("status")
      .execute()
  );
  assert.deepEqual(exceptionalStates, [
    { status: "not_evaluated", reason: "actor_not_user" },
    { status: "unavailable", reason: "identity_mismatch" }
  ]);
  assert.equal(fakeGitHubClient.graphqlCalls, 3);

  await withTenantTransaction(database, created.result.tenantId, (transaction) =>
    transaction
      .updateTable("app.outbox_events")
      .set({
        state: "published",
        published_at: new Date(),
        lease_token: null,
        lease_expires_at: null
      })
      .where("state", "!=", "published")
      .execute()
  );

  const durableHead = "9".repeat(40);
  const durablePullRequestNodeId = `PR_phase2_durable_${installationId}`;
  const durableEnvelope = pullRequestEnvelope(
    "opened",
    durableHead,
    "2026-07-21T10:04:00Z"
  );
  durableEnvelope.pullRequest.id += 100;
  durableEnvelope.pullRequest.number = 18;
  durableEnvelope.pullRequest.nodeId = durablePullRequestNodeId;
  const durable = await accept(database, durableEnvelope);
  durableDeliveryId = durable.deliveryId;

  const temporalAddress = process.env.TEMPORAL_ADDRESS ?? "127.0.0.1:7233";
  const connection = await NativeConnection.connect({ address: temporalAddress });
  const temporalClient = new Client({ connection, namespace: "default" });
  const durableProvider = new FakeGitHubProvider(durableHead);
  const taskQueue = `mergesignal-phase2-${installationId}`;
  const worker = await Worker.create({
    activities: createActivities(database, {
      client: fakeGitHubClient,
      outputProvider: durableProvider,
      appId,
      appOrigin: "https://mergesignal.example.test"
    }),
    connection,
    namespace: "default",
    taskQueue,
    workflowsPath: resolve("packages/workflows/dist/workflows.js")
  });
  const relayAbort = new AbortController();
  const workerPromise = worker.run();
  const relayPromise = runOutboxRelay({
    database,
    temporalClient,
    environment: {
      TEMPORAL_TASK_QUEUE: taskQueue,
      GITHUB_APP_ID: appId.toString()
    },
    signal: relayAbort.signal
  });
  try {
    const durableState = await waitForDurablePublication(
      database,
      created.result.tenantId,
      durablePullRequestNodeId
    );
    assert.equal(durableState.cursor.head_sha, durableHead);
    assert.equal(durableProvider.comments.length, 1);
    assert.equal(durableProvider.checks.length, 1);
    assert.match(durableProvider.comments[0].body, /\d+\/100/);
  } finally {
    relayAbort.abort();
    worker.shutdown();
    await Promise.allSettled([workerPromise, relayPromise]);
    await connection.close();
  }

  process.stdout.write(
    `MVP GitHub reputation lifecycle valid installation=${installationId} generations=${finalState.cursor.generation} assessments=${finalState.assessments.count} comments=${provider.comments.length} currentHead=${finalState.cursor.head_sha} durableWorkflow=true\n`
  );
} finally {
  await database.destroy();
}
