import { createHash, createHmac } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import canonicalize from "canonicalize";

const root = resolve(import.meta.dirname, "..");
const checkMode = process.argv.includes("--check");
const stagedWrites = new Map();

async function readJson(relativePath) {
  return JSON.parse(await readFile(resolve(root, relativePath), "utf8"));
}

async function writeJson(relativePath, value) {
  stagedWrites.set(relativePath, `${JSON.stringify(value, null, 2)}\n`);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function digest(value) {
  return createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}

function databaseUniquenessReceipt({ receiptId, relation, constraintName, key, rowIdentity, transactionId, databaseCommitToken, committedAt }) {
  const core = {
    schemaVersion: "1.0.0",
    receiptId,
    relation,
    constraintName,
    keyDigest: digest({ domain: `${constraintName}-key-v1`, key }),
    rowIdentity,
    transactionId,
    databaseCommitToken,
    isolationLevel: "serializable",
    outcome: "committed",
    committedAt
  };
  return { ...core, receiptDigest: digest(core) };
}

function boundedEvidenceExemplars(sortedPopulation, maximum = 64) {
  if (sortedPopulation.length <= maximum) return sortedPopulation;
  return Array.from({ length: maximum }, (_, index) =>
    sortedPopulation[Math.floor((index * (sortedPopulation.length - 1)) / (maximum - 1))]
  );
}

const fixtureTargetAliasSecret = "phase0-fixture-target-alias-secret-v1";
const fixtureSafetySecret = "phase0-fixture-safety-secret-v1";

function hmac(secret, value) {
  return createHmac("sha256", secret).update(canonicalize(value), "utf8").digest("hex");
}

function normalizePathFamily(path) {
  return path.toLowerCase().replace(/\.(?:test|spec)(?=\.[^/.]+$)/, "").replace(/\.[^/.]+$/, "")
    .split("/").filter((part) => !["src", "test", "tests", "__tests__"].includes(part)).join("/");
}

const allowedTechnicalLanguages = new Set([
  "c", "c++", "c#", "css", "go", "html", "java", "javascript", "kotlin", "php",
  "python", "ruby", "rust", "shell", "swift", "typescript"
]);
const allowedTechnicalDomains = new Set([
  "ai", "api", "cli", "database", "devtools", "github-app", "mobile", "npm", "security", "web"
]);

function sanitizeTechnicalContextToken(value, kind) {
  const normalized = String(value).normalize("NFKC").toLowerCase().trim();
  if (kind === "language") return allowedTechnicalLanguages.has(normalized) ? normalized : "opaque";
  if (kind === "domain") return allowedTechnicalDomains.has(normalized) ? normalized : "opaque";
  const segments = normalized.split(/[\\/]+/).filter(Boolean);
  const basename = segments.at(-1) ?? "";
  if (segments.some((part) => ["test", "tests", "__tests__", "spec", "specs"].includes(part)) || /\.(?:test|spec)\./.test(basename)) return "tests";
  if (segments.some((part) => ["doc", "docs", "documentation"].includes(part)) || /^(?:readme|changelog|license)(?:\.|$)/.test(basename)) return "documentation";
  if (segments.includes(".github") || segments.some((part) => ["ci", ".circleci"].includes(part))) return "ci";
  if (/^(?:package(?:-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|cargo\.lock|go\.(?:mod|sum)|requirements.*\.txt)$/.test(basename)) return "dependencies";
  if (segments.some((part) => ["dist", "build", "generated", "vendor"].includes(part))) return "generated";
  if (/\.(?:json|ya?ml|toml|ini|conf|config)$/.test(basename)) return "configuration";
  return "source";
}

function technicalContext(items, available = true) {
  if (!available) return { sanitizerVersion: "technical-context-sanitizer-v2", available: false, languages: [], domains: [], pathFamilies: [] };
  const languages = new Set();
  const domains = new Set();
  const pathFamilies = new Set();
  for (const item of items) {
    const payload = item.canonicalPayload;
    if (item.type === "REPOSITORY_LANGUAGE") languages.add(sanitizeTechnicalContextToken(payload.language, "language"));
    if (item.type === "REPOSITORY_TOPIC") domains.add(sanitizeTechnicalContextToken(payload.topic, "domain"));
    if (item.type === "DEPENDENCY_ECOSYSTEM") domains.add(sanitizeTechnicalContextToken(payload.ecosystem, "domain"));
    if (item.type === "CHANGED_PATH") pathFamilies.add(sanitizeTechnicalContextToken(normalizePathFamily(payload.path), "path"));
    if (item.type === "RELEVANCE_COMPARISON") {
      payload.languageMatches.forEach((value) => languages.add(sanitizeTechnicalContextToken(value, "language")));
      payload.domainMatches.forEach((value) => domains.add(sanitizeTechnicalContextToken(value, "domain")));
      payload.pathMatches.forEach((value) => pathFamilies.add(sanitizeTechnicalContextToken(value.pathFamily, "path")));
    }
  }
  return {
    sanitizerVersion: "technical-context-sanitizer-v2",
    available: true,
    languages: [...languages].filter(Boolean).sort(compareUtf8).slice(0, 16),
    domains: [...domains].filter(Boolean).sort(compareUtf8).slice(0, 16),
    pathFamilies: [...pathFamilies].filter(Boolean).sort(compareUtf8).slice(0, 16)
  };
}

function itemRevision(item) {
  return digest(item);
}

function publicationStreamProjection(event) {
  const projected = structuredClone(event);
  delete projected.publicationHeadRevision;
  delete projected.publicationHeadDigest;
  delete projected.publicationSnapshotToken;
  return projected;
}

function lifecycleStreamHead(streamKind, aggregateId, events, serializableReadAt, databaseSnapshotToken) {
  const ordered = [...events].sort((left, right) => left.lifecycleRevision - right.lifecycleRevision);
  return {
    schemaVersion: "1.0.0",
    streamKind,
    aggregateId,
    highWaterRevision: ordered.at(-1).lifecycleRevision,
    eventCount: ordered.length,
    streamDigest: digest(streamKind === "publication" ? ordered.map(publicationStreamProjection) : ordered),
    databaseSnapshotToken,
    serializableReadAt
  };
}

function providerLocatorFor(item) {
  const url = new URL(item.sourceUrl);
  const segments = url.pathname.split("/").filter(Boolean);
  if (["ACCOUNT_CREATED", "CONTRIBUTION_YEAR"].includes(item.type)) {
    return { kind: "actor", nodeId: item.subjectGithubNodeId, login: segments[0] };
  }
  return {
    kind: "repository",
    nodeId: item.canonicalPayload.repositoryNodeId ?? item.repositoryNodeId,
    nameWithOwner: `${segments[0]}/${segments[1]}`
  };
}

function canonicalSourceUrl(item) {
  const locator = item.providerLocator;
  if (locator.kind === "actor") return `https://github.com/${locator.login}`;
  const base = `https://github.com/${locator.nameWithOwner}`;
  const payload = item.canonicalPayload;
  if (["REPOSITORY_LANGUAGE", "REPOSITORY_TOPIC"].includes(item.type)) return base;
  if (item.type === "LINKED_ISSUE") return `${base}/issues/${payload.issueNumber}`;
  const pullRequest = `${base}/pull/${payload.pullRequestNumber}`;
  if (["CHANGED_PATH", "PATCH_FILESET_STATUS"].includes(item.type)) return `${pullRequest}/files`;
  if (item.type === "CI_CHECK_STATE") return `${pullRequest}/checks`;
  if (item.type === "FOLLOW_UP_COMMIT") return `${pullRequest}/commits`;
  return pullRequest;
}

function riskPolicyDigest(payload) {
  return digest({
    installationId: payload.installationId,
    repositoryNodeId: payload.repositoryNodeId,
    policyId: payload.policyId,
    policyVersion: payload.policyVersion,
    effectiveFrom: payload.effectiveFrom,
    effectiveUntil: payload.effectiveUntil,
    reviewPriorityEnabled: payload.reviewPriorityEnabled,
    configurationSource: payload.configurationSource,
    rules: payload.rules
  });
}

function riskPolicyConfigurationDigest(payload) {
  return digest({
    reviewPriorityEnabled: payload.reviewPriorityEnabled,
    rules: payload.rules
  });
}

function classifyPathLanguage(path, policy) {
  const normalized = policy.caseSensitive ? path : path.toLowerCase();
  const extensions = Object.keys(policy.extensionMap).sort((left, right) => right.length - left.length);
  const extension = extensions.find((candidate) => normalized.endsWith(candidate));
  return extension === undefined ? policy.fallback : policy.extensionMap[extension];
}

const manifestPath = "contracts/examples/evidence-snapshot.json";
const assessmentPath = "contracts/examples/reputation-assessment.json";
const publicCommentPath = "contracts/examples/pr-comment-render.public.json";
const privateCommentPath = "contracts/examples/pr-comment-render.private.json";
const preVisibilityPath = "contracts/examples/source-visibility-validation.pre.json";
const postVisibilityPath = "contracts/examples/source-visibility-validation.post.json";
const postCheckVisibilityPath = "contracts/examples/source-visibility-validation.post-check.json";
const contextualizationRequestPath = "contracts/examples/contextualization-request.json";
const contextualizationEnvelopePath = "contracts/examples/contextualization-request-envelope.json";
const contextualizationOutputPath = "contracts/examples/contextualization-output.json";
const contextualizationResponseEnvelopePath = "contracts/examples/contextualization-response-envelope.json";
const contextualizationRequestLedgerSentPath = "contracts/examples/contextualization-request-ledger.sent.json";
const contextualizationRequestLedgerAcceptedPath = "contracts/examples/contextualization-request-ledger.accepted.json";
const contextualizationRequestLedgerHeadPath = "contracts/examples/contextualization-request-ledger-head.json";
const outputCursorPath = "contracts/examples/pr-output-cursor.json";
const outputCursorPrePath = "contracts/examples/pr-output-cursor.pre.json";
const outputCursorPostCommentPath = "contracts/examples/pr-output-cursor.post-comment.json";
const outputCursorHeadPath = "contracts/examples/pr-output-cursor-head.json";
const deletionOutputCursorPath = "contracts/examples/pr-output-cursor.deletion.json";
const deletionOutputCursorHeadPath = "contracts/examples/pr-output-cursor-head.deletion.json";
const commentOwnershipPath = "contracts/examples/comment-ownership-observation.json";
const deletionCommentOwnershipPath = "contracts/examples/comment-ownership-observation.deletion.json";
const preCommentInventoryPath = "contracts/examples/comment-inventory-observation.pre.json";
const postCommentInventoryPath = "contracts/examples/comment-inventory-observation.post.json";
const deletionCommentInventoryPath = "contracts/examples/comment-inventory-observation.deletion.json";
const commentDeletionAuthorityPath = "contracts/examples/comment-deletion-authority.json";
const outputMutationLeasePath = "contracts/examples/pr-output-mutation-lease.json";
const retentionStreamHeadPath = "contracts/examples/retention-stream-head.json";
const publicationStreamHeadPath = "contracts/examples/publication-stream-head.json";
const commentRemovalStreamHeadPath = "contracts/examples/comment-removal-stream-head.json";
const detailedReportAuthorizationPath = "contracts/examples/detailed-report-authorization.json";
const detailedReportAuthorityPath = "contracts/examples/detailed-report-authority.json";
const detailedReportNonceConsumptionPath = "contracts/examples/detailed-report-nonce-consumption.json";
const detailedReportProjectionPath = "contracts/examples/detailed-report-projection.json";
const githubAppIdentityObservationPath = "contracts/examples/github-app-identity-observation.json";
const commentRemovalPaths = [
  "contracts/examples/comment-removal-state.queued.json",
  "contracts/examples/comment-removal-state.removing.json",
  "contracts/examples/comment-removal-state.json"
];
const featureArtifactPath = "contracts/version-artifacts/features-v1.json";
const publicationPaths = [
  "contracts/examples/publication-state.queued.json",
  "contracts/examples/publication-state.publishing.json",
  "contracts/examples/publication-state.json",
  "contracts/examples/publication-state.failure.queued.json",
  "contracts/examples/publication-state.failure.publishing.json",
  "contracts/examples/publication-state.failure.json",
  "contracts/examples/publication-state.superseded.queued.json",
  "contracts/examples/publication-state.superseded.publishing.json",
  "contracts/examples/publication-state.superseded.json",
  "contracts/examples/publication-state.repair.json",
];

const [manifest, assessment, publicComment, privateComment, preVisibility, postVisibility, postCheckVisibility, retention, versionRegistry, featurePolicy, reasonRegistry, modelConfig] =
  await Promise.all([
    readJson(manifestPath),
    readJson(assessmentPath),
    readJson(publicCommentPath),
    readJson(privateCommentPath),
    readJson(preVisibilityPath),
    readJson(postVisibilityPath),
    readJson(postCheckVisibilityPath),
    readJson("contracts/examples/assessment-retention-state.json"),
    readJson("contracts/version-registry.json"),
    readJson(featureArtifactPath),
    readJson("contracts/reason-codes.json"),
    readJson("contracts/version-artifacts/model-gpt-5.6-sol.json")
  ]);
const featureEvaluator = await import(
  `${pathToFileURL(resolve(root, featurePolicy.evaluatorArtifactPath)).href}?refresh=phase0`
);

manifest.capturedAt = assessment.evidenceSnapshot.capturedAt;
Object.assign(retention, {
  transactionId: "80808080-8080-4080-8080-808080808080",
  databaseCommitToken: digest({ fixtureRetentionCommit: 1 }),
  outboxBatchId: null
});
const engineEntry = versionRegistry.entries.find((entry) =>
  entry.kind === "engine" &&
  new Date(entry.effectiveFrom) <= new Date(assessment.createdAt) &&
  (entry.effectiveUntil === null || new Date(assessment.createdAt) < new Date(entry.effectiveUntil))
);
const engineArtifact = await readJson(engineEntry.artifactPath);
const assessmentEngine = await import(
  `${pathToFileURL(resolve(root, engineArtifact.evaluatorArtifactPath)).href}?refresh=phase0-engine`
);
assessment.versions.engine = engineEntry.version;
assessment.versionDigests.engine = engineEntry.artifactDigest;
manifest.versions = {
  engine: assessment.versions.engine,
  evidence: assessment.versions.evidence,
  features: assessment.versions.features
};
manifest.versionDigests = {
  engine: assessment.versionDigests.engine,
  evidence: assessment.versionDigests.evidence,
  features: assessment.versionDigests.features
};

for (const item of manifest.items.filter((candidate) => candidate.type === "PULL_REQUEST_OPENED")) {
  item.canonicalPayload.metadataStructure =
    item.evidenceId === "ev_pr_opened"
      ? {
          titleTokenClasses: ["word", "word", "code"],
          bodySectionKinds: ["summary", "changes", "testing"],
          referenceKinds: ["issue"]
        }
      : {
          titleTokenClasses: ["word", "code"],
          bodySectionKinds: ["summary", "testing"],
          referenceKinds: []
        };
  item.canonicalPayload.metadataStructureFingerprint = digest(item.canonicalPayload.metadataStructure);
  item.canonicalPayload.repositoryTemplateStructure = null;
  item.canonicalPayload.templateAdjustedStructure = structuredClone(item.canonicalPayload.metadataStructure);
  item.canonicalPayload.templateAdjustedFingerprint = digest(item.canonicalPayload.templateAdjustedStructure);
  item.canonicalPayload.informativeFeatureCount = Object.values(
    item.canonicalPayload.templateAdjustedStructure
  ).reduce((count, values) => count + values.length, 0);
}

const followUp = manifest.items.find((item) => item.evidenceId === "ev_follow");
followUp.canonicalPayload.commitAuthorNodeId = assessment.subject.githubNodeId;

let historicalFileset = manifest.items.find((item) => item.evidenceId === "ev_historical_fileset");
if (!historicalFileset) {
  historicalFileset = {
    evidenceId: "ev_historical_fileset",
    type: "PATCH_FILESET_STATUS",
    visibility: "PUBLIC_GLOBAL",
    subjectGithubNodeId: assessment.subject.githubNodeId,
    providerNodeId: "PR_public_12",
    repositoryNodeId: "R_public_project",
    observedAt: manifest.capturedAt,
    collectorVersion: "github-rest-v1",
    collectionRunId: manifest.items[0].collectionRunId,
    canonicalPayload: {
      pullRequestNodeId: "PR_public_12",
      repositoryNodeId: "R_public_project",
      pullRequestNumber: 12,
      headSha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      collectionState: "complete",
      providerTotalCount: 1,
      collectedFileCount: 1,
      pageInfoComplete: true,
      complete: true
    },
    sourceUrl: "https://github.com/example/project/pull/12/files"
  };
  const relevanceIndex = manifest.items.findIndex((item) => item.evidenceId === "ev_relevance");
  manifest.items.splice(relevanceIndex, 0, historicalFileset);
}

for (const item of manifest.items.filter((candidate) => candidate.visibility === "PUBLIC_GLOBAL")) {
  item.providerLocator = providerLocatorFor(item);
  item.sourceUrl = canonicalSourceUrl(item);
}

const relevance = manifest.items.find((item) => item.evidenceId === "ev_relevance");
for (const path of manifest.items.filter((item) => item.type === "CHANGED_PATH")) {
  path.canonicalPayload.language = classifyPathLanguage(
    path.canonicalPayload.path,
    featurePolicy.pathLanguage
  );
  path.canonicalPayload.languageFeatureVersion = featurePolicy.pathLanguage.version;
}
for (const fileset of manifest.items.filter((item) => item.type === "PATCH_FILESET_STATUS")) {
  const matchingPath = manifest.items.find((candidate) =>
    candidate.type === "CHANGED_PATH" &&
    candidate.canonicalPayload.pullRequestNodeId === fileset.canonicalPayload.pullRequestNodeId &&
    candidate.canonicalPayload.headSha === fileset.canonicalPayload.headSha
  );
  if (!matchingPath?.eventAt) throw new Error(`Fileset ${fileset.evidenceId} cannot resolve its revision timestamp`);
  fileset.canonicalPayload.revisionAt = matchingPath.eventAt;
  fileset.eventAt = matchingPath.eventAt;
}
Object.assign(relevance.canonicalPayload, {
  historicalHeadSha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  historicalFilesetEvidenceId: "ev_historical_fileset",
  targetHeadSha: assessment.target.headSha,
  targetFilesetEvidenceId: "ev_fileset"
});
relevance.derivation.inputEvidenceIds = [...new Set([
  ...relevance.derivation.inputEvidenceIds,
  "ev_historical_fileset",
  "ev_fileset"
])];

const riskPolicy = manifest.items.find((item) => item.evidenceId === "ev_risk_policy");
const policyConfigurationDigest = riskPolicyConfigurationDigest(riskPolicy.canonicalPayload);
const authorizationSnapshotToken = digest({ fixtureAuthorizationSnapshot: 1 });
const dashboardRevisionPayload = {
  installationId: assessment.target.installationId,
  repositoryNodeId: assessment.target.repositoryNodeId,
  revisionId: "13131313-1313-4131-8131-131313131313",
  revisionSequence: 1,
  authorizedHeadRevision: 1,
  actorGithubNodeId: "U_maintainer_admin",
  configurationDigest: policyConfigurationDigest,
  authorizationNonce: "14141414-1414-4141-8141-141414141414",
  authorizationSnapshotToken,
  recordedAt: "2025-12-31T23:59:59Z"
};
const policyProvenanceItems = [
  {
    evidenceId: "ev_repository_visibility",
    type: "REPOSITORY_VISIBILITY_SNAPSHOT",
    visibility: "TARGET_REPOSITORY_PRIVATE",
    subjectGithubNodeId: assessment.subject.githubNodeId,
    repositoryNodeId: assessment.target.repositoryNodeId,
    observedAt: manifest.capturedAt,
    collectorVersion: "github-rest-v1",
    collectionRunId: riskPolicy.collectionRunId,
    canonicalPayload: {
      installationId: assessment.target.installationId,
      repositoryNodeId: assessment.target.repositoryNodeId,
      visibility: "public",
      providerObservedAt: manifest.capturedAt
    }
  },
  {
    evidenceId: "ev_policy_admin",
    type: "REPOSITORY_ADMIN_PERMISSION",
    visibility: "TARGET_REPOSITORY_PRIVATE",
    subjectGithubNodeId: assessment.subject.githubNodeId,
    repositoryNodeId: assessment.target.repositoryNodeId,
    observedAt: "2025-12-31T23:59:59Z",
    collectorVersion: "github-rest-v1",
    collectionRunId: riskPolicy.collectionRunId,
    canonicalPayload: {
      installationId: assessment.target.installationId,
      repositoryNodeId: assessment.target.repositoryNodeId,
      actorGithubNodeId: "U_maintainer_admin",
      permission: "admin",
      state: "granted",
      providerObservedAt: "2025-12-31T23:59:59Z",
      authorizationForRevisionId: "13131313-1313-4131-8131-131313131313",
      authorizationForRevisionSequence: 1,
      authorizationHeadRevision: 1,
      authorizationNonce: "14141414-1414-4141-8141-141414141414",
      authorizationSnapshotToken
    }
  },
  {
    evidenceId: "ev_policy_revision",
    type: "DASHBOARD_POLICY_REVISION",
    visibility: "TARGET_REPOSITORY_PRIVATE",
    subjectGithubNodeId: assessment.subject.githubNodeId,
    repositoryNodeId: assessment.target.repositoryNodeId,
    observedAt: "2025-12-31T23:59:59Z",
    collectorVersion: "policy-engine-v1",
    collectionRunId: riskPolicy.collectionRunId,
    canonicalPayload: dashboardRevisionPayload
  },
  {
    evidenceId: "ev_policy_head",
    type: "DASHBOARD_POLICY_STREAM_HEAD",
    visibility: "TARGET_REPOSITORY_PRIVATE",
    subjectGithubNodeId: assessment.subject.githubNodeId,
    repositoryNodeId: assessment.target.repositoryNodeId,
    observedAt: "2025-12-31T23:59:59.500Z",
    collectorVersion: "policy-engine-v1",
    collectionRunId: riskPolicy.collectionRunId,
    canonicalPayload: {
      installationId: assessment.target.installationId,
      repositoryNodeId: assessment.target.repositoryNodeId,
      streamId: "15151515-1515-4151-8151-151515151515",
      highWaterRevision: dashboardRevisionPayload.revisionSequence,
      highWaterRevisionId: dashboardRevisionPayload.revisionId,
      streamDigest: digest([dashboardRevisionPayload]),
      databaseSnapshotToken: authorizationSnapshotToken,
      serializableReadAt: "2025-12-31T23:59:59.500Z"
    }
  }
];
for (const provenanceItem of policyProvenanceItems) {
  const index = manifest.items.findIndex((item) => item.evidenceId === provenanceItem.evidenceId);
  if (index === -1) manifest.items.splice(manifest.items.indexOf(riskPolicy), 0, provenanceItem);
  else manifest.items[index] = provenanceItem;
}
Object.assign(riskPolicy.canonicalPayload, {
  installationId: assessment.target.installationId,
  policyId: "12121212-1212-4121-8121-121212121212",
  effectiveFrom: "2026-01-01T00:00:00Z",
  effectiveUntil: null,
  reviewPriorityEnabled: true,
  configurationSource: {
    kind: "dashboard_revision",
    revisionEvidenceId: "ev_policy_revision",
    adminPermissionEvidenceId: "ev_policy_admin",
    policyHeadEvidenceId: "ev_policy_head"
  }
});
riskPolicy.visibility = "TARGET_REPOSITORY_PRIVATE";
riskPolicy.derivation = {
  version: "repository-risk-policy-v1",
  inputEvidenceIds: ["ev_policy_admin", "ev_policy_revision", "ev_policy_head"]
};
riskPolicy.canonicalPayload.policyDigest = riskPolicyDigest(riskPolicy.canonicalPayload);

const sensitive = manifest.items.find((item) => item.evidenceId === "ev_sensitive");
Object.assign(sensitive.canonicalPayload, {
  policyId: riskPolicy.canonicalPayload.policyId,
  policyDigest: riskPolicy.canonicalPayload.policyDigest
});
sensitive.visibility = "TARGET_REPOSITORY_PRIVATE";
assessment.target.riskPolicy = {
  installationId: riskPolicy.canonicalPayload.installationId,
  policyId: riskPolicy.canonicalPayload.policyId,
  policyVersion: riskPolicy.canonicalPayload.policyVersion,
  policyDigest: riskPolicy.canonicalPayload.policyDigest,
  reviewPriorityEnabled: riskPolicy.canonicalPayload.reviewPriorityEnabled
};
assessment.target.visibilityEvidenceId = "ev_repository_visibility";
assessment.patchContext.evidenceIds = [...new Set([
  ...assessment.patchContext.evidenceIds,
  "ev_fileset"
])];

const selectedContextualizationReasonCodes = new Set(
  assessment.explanation.claims.map((claim) => claim.reasonCode)
);
for (const claim of assessment.explanation.claims) delete claim.text;

const coverageItem = manifest.items.find((item) => item.evidenceId === "ev_coverage");
const coverage = coverageItem.canonicalPayload;
const capture = new Date(manifest.capturedAt);
const firstCoverageYear = capture.getUTCFullYear() - coverage.requestedWindowYears + 1;
Object.assign(coverage, {
  windowStart: `${firstCoverageYear}-01-01T00:00:00Z`,
  windowEnd: manifest.capturedAt,
  freshAsOf: manifest.capturedAt,
  freshnessPolicy: featurePolicy.publicHistoryFreshness,
  freshness: "current",
  confidencePolicy: featurePolicy.coverageConfidence.version,
  confidence: 1,
  partialSources: []
});
assessment.coverage.confidence = coverage.confidence;
assessment.coverage.evidenceIds = [
  coverageItem.evidenceId,
  "ev_author_available",
  "ev_actor_type"
];

function coverageEventTimestamp(item) {
  if (item.eventAt !== undefined) return item.eventAt;
  if (item.type === "PATCH_FILESET_STATUS") {
    const payload = item.canonicalPayload;
    const changedPathTimes = new Set(
      manifest.items
        .filter((candidate) =>
          candidate.type === "CHANGED_PATH" &&
          candidate.canonicalPayload.pullRequestNodeId === payload.pullRequestNodeId &&
          candidate.canonicalPayload.headSha === payload.headSha
        )
        .map((candidate) => candidate.eventAt)
    );
    if (changedPathTimes.has(undefined) || changedPathTimes.size > 1) {
      throw new Error(`Fileset ${item.evidenceId} has no unique changed-path event timestamp`);
    }
    if (changedPathTimes.size === 1) return [...changedPathTimes][0];
    const opened = manifest.items.filter((candidate) =>
      candidate.type === "PULL_REQUEST_OPENED" &&
      candidate.canonicalPayload.pullRequestNodeId === payload.pullRequestNodeId
    );
    if (opened.length !== 1) throw new Error(`Fileset ${item.evidenceId} cannot resolve its pull-request event timestamp`);
    return opened[0].eventAt;
  }
  throw new Error(`Coverage item ${item.evidenceId} has no deterministic event timestamp`);
}

function makeCoveragePartition(definition, year = null) {
  const requestedStart = year === null ? coverage.windowStart : `${year}-01-01T00:00:00Z`;
  const requestedEnd =
    year === null
      ? coverage.windowEnd
      : year === capture.getUTCFullYear()
        ? coverage.windowEnd
        : `${year}-12-31T23:59:59.999Z`;
  const candidates = manifest.items
    .filter(
      (item) =>
        item.visibility === "PUBLIC_GLOBAL" &&
        item.subjectGithubNodeId === coverageItem.subjectGithubNodeId &&
        item.collectionRunId === coverageItem.collectionRunId &&
        definition.evidenceTypes.includes(item.type) &&
        (year === null ||
          (new Date(coverageEventTimestamp(item)) >= new Date(requestedStart) &&
            new Date(coverageEventTimestamp(item)) <= new Date(requestedEnd)))
    )
    .sort((left, right) => compareUtf8(left.evidenceId, right.evidenceId));
  return {
    partitionKey: year === null ? definition.key : `${definition.key}_${year}`,
    queryVersion: definition.queryVersion,
    temporalBasis: definition.temporalBasis,
    evidenceTypes: definition.evidenceTypes,
    state: "complete",
    requestedStart,
    requestedEnd,
    completedStart: requestedStart,
    completedEnd: requestedEnd,
    providerTotalCount: candidates.length,
    collectedCount: candidates.length,
    pageInfoComplete: true,
    observedAt: manifest.capturedAt,
    limitationReasons: [],
    candidateEvidenceIds: candidates.map((item) => item.evidenceId),
    candidateSetDigest: digest(candidates)
  };
}

coverage.sourcePartitions = featurePolicy.coverageQueryPlan.partitions.flatMap((definition) =>
  definition.mode === "singleton"
    ? [makeCoveragePartition(definition)]
    : Array.from({ length: coverage.requestedWindowYears }, (_, index) =>
        makeCoveragePartition(definition, firstCoverageYear + index)
      )
);
coverage.completeYears = Array.from({ length: coverage.requestedWindowYears }, (_, index) => firstCoverageYear + index)
  .filter((year) =>
    featurePolicy.coverageQueryPlan.partitions
      .filter((definition) => definition.countsTowardCompleteYears)
      .every((definition) =>
        coverage.sourcePartitions.some(
          (partition) => partition.partitionKey === `${definition.key}_${year}` && partition.state === "complete"
        )
      )
  ).length;
coverage.freshAsOf = coverage.sourcePartitions
  .map((partition) => partition.observedAt)
  .reduce((earliest, candidate) =>
    new Date(candidate).getTime() < new Date(earliest).getTime() ? candidate : earliest
  );

assessment.versionDigests = Object.fromEntries(
  Object.entries(assessment.versions).map(([kind, version]) => {
    const entry = versionRegistry.entries.find(
      (candidate) => candidate.kind === kind && candidate.version === version
    );
    if (!entry) throw new Error(`Assessment references missing registry entry ${kind}:${version}`);
    return [kind, entry.artifactDigest];
  })
);
manifest.versions = {
  engine: assessment.versions.engine,
  evidence: assessment.versions.evidence,
  features: assessment.versions.features
};
manifest.versionDigests = {
  engine: assessment.versionDigests.engine,
  evidence: assessment.versionDigests.evidence,
  features: assessment.versionDigests.features
};

function manifestHash(value) {
  return digest({
    schemaVersion: value.schemaVersion,
    snapshotId: value.snapshotId,
    capturedAt: value.capturedAt,
    items: [...value.items].sort((left, right) => compareUtf8(left.evidenceId, right.evidenceId))
  });
}

assessment.evidenceSnapshot.evidenceIds = manifest.items.map((item) => item.evidenceId);
assessment.evidenceSnapshot.canonicalHash = manifestHash(manifest);

const byId = new Map(manifest.items.map((item) => [item.evidenceId, item]));
const reasonByCode = new Map(reasonRegistry.codes.map((reason) => [reason.code, reason]));
const coverageItemForContext = byId.get(assessment.coverage.evidenceIds[0]);
const coverageRunIdForContext = coverageItemForContext.collectionRunId;
const authoritativeHistoryIds = assessmentEngine.buildAuthoritativeHistoryEvidenceIds({
  coverageItem: coverageItemForContext,
  manifestItems: manifest.items,
  assessment,
  evidenceById: byId,
  features: featurePolicy,
  assert(condition, message) {
    if (!condition) throw new Error(message);
  }
});
const dimensionOrder = [
  "tenure_continuity",
  "independent_open_source_record",
  "merge_follow_through",
  "collaboration",
  "relevant_experience",
  "integrity_gaming_resistance"
];
function contextualizationEvidenceForReason(reason) {
  return assessmentEngine.authoritativeReasonEvidenceIds(
    reason,
    assessment,
    byId,
    authoritativeHistoryIds
  );
}
for (const dimension of dimensionOrder) {
  if (assessment.dimensions[dimension].reasonCodes.length === 0) continue;
  assessment.dimensions[dimension].evidenceIds = [...new Set(
    assessment.dimensions[dimension].reasonCodes.flatMap((reasonCode) =>
      contextualizationEvidenceForReason(reasonByCode.get(reasonCode))
    )
  )].sort(compareUtf8);
}
const contextualizationConstructionMetrics = {};
const contextualizationCandidates = assessmentEngine.buildContextualizationCandidates({
  assessment,
  evidenceById: byId,
  reasonByCode,
  authoritativeHistoryEvidenceIds: authoritativeHistoryIds,
  features: featurePolicy,
  assert(condition, message) {
    if (!condition) throw new Error(message);
  },
  metrics: contextualizationConstructionMetrics
});
assessment.explanation.candidatePacket = {
  version: "contextualization-candidates-v1",
  candidates: contextualizationCandidates,
  digest: digest({
    version: "contextualization-candidates-v1",
    candidates: contextualizationCandidates
  })
};
assessment.explanation.claims = contextualizationCandidates
  .filter((candidate) => selectedContextualizationReasonCodes.has(candidate.reasonCode))
  .slice(0, 3);
assessment.explanation.evidenceIds = [...new Set(
  assessment.explanation.claims.flatMap((claim) => claim.witnessEvidenceIds)
)];
const requestAlias = "78787878-7878-4878-8878-787878787878";
const requestNonce = "89898989-8989-4989-8989-898989898989";
const targetBinding = {
  installationId: assessment.target.installationId,
  repositoryNodeId: assessment.target.repositoryNodeId,
  pullRequestNodeId: assessment.target.pullRequestNodeId,
  pullRequestNumber: assessment.target.pullRequestNumber,
  headSha: assessment.target.headSha,
  generation: assessment.target.generation
};
const candidatePopulations = assessment.explanation.candidatePacket.candidates.map((candidate) => {
  const populationEvidenceIds = contextualizationEvidenceForReason(reasonByCode.get(candidate.reasonCode));
  return {
    claimId: candidate.claimId,
    populationEvidenceIds,
    populationCommitment: hmac(fixtureTargetAliasSecret, {
      domain: "population-commitment-v1",
      requestAlias,
      requestNonce,
      claimId: candidate.claimId,
      populationEvidenceIds
    })
  };
});
const populationByClaimId = new Map(candidatePopulations.map((entry) => [entry.claimId, entry]));
const providerEligibleCandidates = assessment.explanation.candidatePacket.candidates.filter((candidate) => {
  const population = populationByClaimId.get(candidate.claimId).populationEvidenceIds;
  return candidate.witnessEvidenceIds.length <= 64 && population.every((id) =>
    ["PUBLIC_GLOBAL", "PUBLIC_DERIVED"].includes(byId.get(id)?.visibility)
  );
});
const contextualizationEvidenceIds = [...new Set(
  providerEligibleCandidates.flatMap((candidate) => [...candidate.evidenceIds, ...candidate.witnessEvidenceIds])
)].sort(compareUtf8);
const evidenceAliases = contextualizationEvidenceIds.map((evidenceId) => ({
  evidenceId,
  evidenceAlias: `ev_${hmac(fixtureTargetAliasSecret, {
    domain: "evidence-alias-v1",
    requestAlias,
    requestNonce,
    evidenceId
  })}`
}));
const aliasByEvidenceId = new Map(evidenceAliases.map((entry) => [entry.evidenceId, entry.evidenceAlias]));
const providerCandidatePacket = {
  version: "contextualization-candidates-v1",
  candidates: providerEligibleCandidates.map((candidate) => ({
    claimId: candidate.claimId,
    reasonCode: candidate.reasonCode,
    populationEvidenceCount: candidate.populationEvidenceCount,
    populationCommitment: populationByClaimId.get(candidate.claimId).populationCommitment,
    witnessMode: candidate.witnessMode,
    witnessEvidenceIds: candidate.witnessEvidenceIds.map((evidenceId) => aliasByEvidenceId.get(evidenceId)),
    evidenceIds: candidate.evidenceIds.map((evidenceId) => aliasByEvidenceId.get(evidenceId))
  }))
};
providerCandidatePacket.digest = digest({
  version: providerCandidatePacket.version,
  candidates: providerCandidatePacket.candidates
});
const contextualizationRequestCore = {
  schemaVersion: "1.0.0",
  requestAlias,
  targetAlias: hmac(fixtureTargetAliasSecret, {
    domain: "target-alias-v1",
    requestAlias,
    requestNonce,
    target: targetBinding
  }),
  safetyIdentifier: hmac(fixtureSafetySecret, {
    domain: "safety-identifier-v1",
    scope: "installation_subject",
    installationId: assessment.target.installationId,
    principal: assessment.subject.githubNodeId
  }),
  versions: structuredClone(assessment.versions),
  versionDigests: structuredClone(assessment.versionDigests),
  targetContext: technicalContext(
    manifest.items.filter((item) =>
      (item.repositoryNodeId ?? item.canonicalPayload.repositoryNodeId) === assessment.target.repositoryNodeId &&
      ["PUBLIC_GLOBAL", "PUBLIC_DERIVED"].includes(item.visibility)
    ),
    assessment.target.repositoryVisibility === "public"
  ),
  candidatePacket: providerCandidatePacket,
  evidenceIndex: contextualizationEvidenceIds.map((evidenceId) => {
    const item = byId.get(evidenceId);
    if (!["PUBLIC_GLOBAL", "PUBLIC_DERIVED"].includes(item.visibility)) {
      throw new Error(`Contextualization request includes restricted evidence ${evidenceId}`);
    }
    return {
      evidenceId: aliasByEvidenceId.get(evidenceId),
      evidenceType: item.type,
      visibility: item.visibility,
      technicalContext: technicalContext([item])
    };
  }).sort((left, right) => compareUtf8(left.evidenceId, right.evidenceId))
};
const contextualizationRequest = {
  ...contextualizationRequestCore,
  requestDigest: digest(contextualizationRequestCore)
};
await writeJson(contextualizationRequestPath, contextualizationRequest);
const contextualizationEnvelopeCore = {
  schemaVersion: "1.0.0",
  requestAlias: contextualizationRequest.requestAlias,
  assessmentId: assessment.assessmentId,
  target: targetBinding,
  requestNonce,
  targetAlias: contextualizationRequest.targetAlias,
  targetAliasKeyVersion: "target-alias-key-v1",
  targetAliasScope: "per_request_target",
  safetyIdentifier: contextualizationRequest.safetyIdentifier,
  safetyKeyVersion: "safety-key-v1",
  safetyScope: "installation_subject",
  safetyPrincipal: assessment.subject.githubNodeId,
  evidenceAliases,
  candidatePopulations,
  instructionArtifactDigest: assessment.versionDigests.prompt,
  requestSchemaArtifactDigest: modelConfig.requestSchemaArtifactDigest,
  responseSchemaArtifactDigest: modelConfig.responseSchemaArtifactDigest,
  modelParametersDigest: digest({
    resolvedModel: modelConfig.resolvedModel,
    reasoningEffort: modelConfig.reasoningEffort,
    tools: modelConfig.tools,
    store: modelConfig.store
  }),
  providerRequestDigest: contextualizationRequest.requestDigest,
  providerInvocationDigest: digest({
    providerRequestDigest: contextualizationRequest.requestDigest,
    instructionArtifactDigest: assessment.versionDigests.prompt,
    requestSchemaArtifactDigest: modelConfig.requestSchemaArtifactDigest,
    responseSchemaArtifactDigest: modelConfig.responseSchemaArtifactDigest,
    modelParametersDigest: digest({
      resolvedModel: modelConfig.resolvedModel,
      reasoningEffort: modelConfig.reasoningEffort,
      tools: modelConfig.tools,
      store: modelConfig.store
    })
  }),
  sentAt: "2026-07-21T00:00:00.500Z"
};
const contextualizationEnvelope = {
  ...contextualizationEnvelopeCore,
  envelopeDigest: digest(contextualizationEnvelopeCore)
};
await writeJson(contextualizationEnvelopePath, contextualizationEnvelope);
const providerClaimsById = new Map(providerCandidatePacket.candidates.map((claim) => [claim.claimId, claim]));
const contextualizationOutputCore = {
  schemaVersion: "1.0.0",
  requestAlias,
  candidatePacketDigest: providerCandidatePacket.digest,
  claims: assessment.explanation.claims.map((claim) => structuredClone(providerClaimsById.get(claim.claimId)))
};
const contextualizationOutput = {
  ...contextualizationOutputCore,
  outputDigest: digest(contextualizationOutputCore)
};
await writeJson(contextualizationOutputPath, contextualizationOutput);
const contextualizationResponseEnvelopeCore = {
  schemaVersion: "1.0.0",
  assessmentId: assessment.assessmentId,
  requestAlias,
  providerRequestDigest: contextualizationRequest.requestDigest,
  providerInvocationDigest: contextualizationEnvelope.providerInvocationDigest,
  candidatePacketDigest: providerCandidatePacket.digest,
  resolvedModel: "gpt-5.6-sol-2026-07-01",
  providerResponseId: "resp_phase0_fixture_001",
  providerOutputDigest: contextualizationOutput.outputDigest,
  receivedAt: "2026-07-21T00:00:01Z"
};
const contextualizationResponseEnvelope = {
  ...contextualizationResponseEnvelopeCore,
  envelopeDigest: digest(contextualizationResponseEnvelopeCore)
};
await writeJson(contextualizationResponseEnvelopePath, contextualizationResponseEnvelope);
const requestLedgerId = "74747474-7474-4474-8474-747474747474";
const requestLedgerSentTransactionId = "74747474-1111-4111-8111-111111111111";
const requestLedgerSentCommitToken = digest({ fixtureContextualizationSentCommit: 1 });
const requestAliasReceipt = databaseUniquenessReceipt({
  receiptId: "74747474-2222-4222-8222-222222222222",
  relation: "contextualization_request_ledger",
  constraintName: "uq_contextualization_request_alias",
  key: { requestAlias },
  rowIdentity: requestLedgerId,
  transactionId: requestLedgerSentTransactionId,
  databaseCommitToken: requestLedgerSentCommitToken,
  committedAt: contextualizationEnvelope.sentAt
});
const requestNonceReceipt = databaseUniquenessReceipt({
  receiptId: "74747474-3333-4333-8333-333333333333",
  relation: "contextualization_request_ledger",
  constraintName: "uq_contextualization_request_nonce",
  key: { requestNonce },
  rowIdentity: requestLedgerId,
  transactionId: requestLedgerSentTransactionId,
  databaseCommitToken: requestLedgerSentCommitToken,
  committedAt: contextualizationEnvelope.sentAt
});
const requestLedgerSentCore = {
  schemaVersion: "1.0.0",
  ledgerId: requestLedgerId,
  transitionId: "75757575-7575-4575-8575-757575757575",
  ledgerRevision: 1,
  previousState: null,
  state: "sent",
  assessmentId: assessment.assessmentId,
  requestEnvelopeDigest: contextualizationEnvelope.envelopeDigest,
  requestAlias,
  requestNonce,
  providerInvocationDigest: contextualizationEnvelope.providerInvocationDigest,
  sentAt: contextualizationEnvelope.sentAt,
  acceptedAt: null,
  providerResponseId: null,
  responseEnvelopeDigest: null,
  transactionId: requestLedgerSentTransactionId,
  databaseCommitToken: requestLedgerSentCommitToken,
  uniquenessReceipts: [requestAliasReceipt, requestNonceReceipt],
  previousCasToken: null,
  createdAt: contextualizationEnvelope.sentAt
};
const requestLedgerSent = { ...requestLedgerSentCore, casToken: digest(requestLedgerSentCore) };
const requestLedgerAcceptedTransactionId = "74747474-4444-4444-8444-444444444444";
const requestLedgerAcceptedCommitToken = digest({ fixtureContextualizationAcceptedCommit: 1 });
const providerResponseReceipt = databaseUniquenessReceipt({
  receiptId: "74747474-5555-4555-8555-555555555555",
  relation: "contextualization_request_ledger",
  constraintName: "uq_contextualization_provider_response_id",
  key: { providerResponseId: contextualizationResponseEnvelope.providerResponseId },
  rowIdentity: requestLedgerId,
  transactionId: requestLedgerAcceptedTransactionId,
  databaseCommitToken: requestLedgerAcceptedCommitToken,
  committedAt: contextualizationResponseEnvelope.receivedAt
});
const requestLedgerAcceptedCore = {
  schemaVersion: "1.0.0",
  ledgerId: requestLedgerSent.ledgerId,
  transitionId: "76767676-7676-4676-8676-767676767676",
  ledgerRevision: 2,
  previousState: "sent",
  state: "accepted",
  assessmentId: assessment.assessmentId,
  requestEnvelopeDigest: contextualizationEnvelope.envelopeDigest,
  requestAlias,
  requestNonce,
  providerInvocationDigest: contextualizationEnvelope.providerInvocationDigest,
  sentAt: contextualizationEnvelope.sentAt,
  acceptedAt: contextualizationResponseEnvelope.receivedAt,
  providerResponseId: contextualizationResponseEnvelope.providerResponseId,
  responseEnvelopeDigest: contextualizationResponseEnvelope.envelopeDigest,
  transactionId: requestLedgerAcceptedTransactionId,
  databaseCommitToken: requestLedgerAcceptedCommitToken,
  uniquenessReceipts: [requestAliasReceipt, requestNonceReceipt, providerResponseReceipt],
  previousCasToken: requestLedgerSent.casToken,
  createdAt: contextualizationResponseEnvelope.receivedAt
};
const requestLedgerAccepted = { ...requestLedgerAcceptedCore, casToken: digest(requestLedgerAcceptedCore) };
const requestLedgerHead = {
  schemaVersion: "1.0.0",
  ledgerId: requestLedgerAccepted.ledgerId,
  assessmentId: assessment.assessmentId,
  highWaterRevision: requestLedgerAccepted.ledgerRevision,
  eventCount: 2,
  state: requestLedgerAccepted.state,
  casToken: requestLedgerAccepted.casToken,
  streamDigest: digest([requestLedgerSent, requestLedgerAccepted]),
  databaseSnapshotToken: digest({ fixtureContextualizationLedgerSnapshot: 1 }),
  serializableReadAt: "2026-07-21T00:00:01.050Z"
};
await writeJson(contextualizationRequestLedgerSentPath, requestLedgerSent);
await writeJson(contextualizationRequestLedgerAcceptedPath, requestLedgerAccepted);
await writeJson(contextualizationRequestLedgerHeadPath, requestLedgerHead);
assessment.explanation.modelRun = {
  requestAlias,
  providerRequestDigest: contextualizationRequest.requestDigest,
  providerInvocationDigest: contextualizationEnvelope.providerInvocationDigest,
  candidatePacketDigest: providerCandidatePacket.digest,
  resolvedModel: contextualizationResponseEnvelope.resolvedModel,
  providerResponseId: contextualizationResponseEnvelope.providerResponseId,
  providerOutputDigest: contextualizationOutput.outputDigest,
  responseEnvelopeDigest: contextualizationResponseEnvelope.envelopeDigest
};
const selected = new Set([
  assessment.target.visibilityEvidenceId,
  ...Object.values(assessment.dimensions).flatMap((dimension) => dimension.evidenceIds),
  ...assessment.patchContext.evidenceIds,
  ...assessment.coverage.evidenceIds,
  ...assessment.explanation.evidenceIds,
  ...assessment.explanation.claims.flatMap((claim) => claim.evidenceIds),
  ...assessment.explanation.claims.flatMap((claim) => claim.witnessEvidenceIds),
  ...assessment.explanation.candidatePacket.candidates.flatMap((candidate) => candidate.evidenceIds),
  ...assessment.explanation.candidatePacket.candidates.flatMap((candidate) => candidate.witnessEvidenceIds)
]);
function includeProvenance(id) {
  const item = byId.get(id);
  const coverageCandidateIds =
    item.type === "PUBLIC_COVERAGE_SUMMARY"
      ? item.canonicalPayload.sourcePartitions.flatMap(
          (partition) => partition.candidateEvidenceIds
        )
      : [];
  for (const inputId of [
    ...(item.derivation?.inputEvidenceIds ?? []),
    ...coverageCandidateIds
  ]) {
    if (!selected.has(inputId)) {
      selected.add(inputId);
      includeProvenance(inputId);
    }
  }
}
for (const id of [...selected]) includeProvenance(id);
const sourceItems = [...selected]
  .sort(compareUtf8)
  .map((id) => byId.get(id));
const sourceSetDigest = digest(sourceItems);

for (const comment of [publicComment, privateComment]) {
  comment.sourceSetDigest = sourceSetDigest;
}

const publications = await Promise.all(publicationPaths.map(readJson));
const outputCursorBase = {
  schemaVersion: "1.0.0",
  cursorId: "67676767-6767-4767-8767-676767676767",
  installationId: assessment.target.installationId,
  repositoryNodeId: assessment.target.repositoryNodeId,
  pullRequestNodeId: assessment.target.pullRequestNodeId,
  pullRequestNumber: assessment.target.pullRequestNumber,
  activeGeneration: assessment.target.generation,
  activeHeadSha: assessment.target.headSha,
  state: "active"
};
function outputCursorEvent(cursorRevision, canonicalCommentId, canonicalCheckRunId, observedAt, previous = null) {
  const core = {
    ...outputCursorBase,
    cursorRevision,
    transitionKind: cursorRevision === 1 ? "initialize" : "publish_same_generation",
    previousCursorDigest: previous?.cursorDigest ?? null,
    canonicalCommentId,
    canonicalCheckRunId,
    databaseSnapshotToken: digest({ fixtureOutputCursorSnapshot: cursorRevision }),
    observedAt
  };
  return { ...core, cursorDigest: digest(core) };
}
const outputCursorPre = outputCursorEvent(1, null, null, "2026-07-21T00:00:01.500Z");
const outputCursorPostComment = outputCursorEvent(
  2,
  publications[2].comment.commentId,
  null,
  "2026-07-21T00:00:03.100Z",
  outputCursorPre
);
const outputCursor = outputCursorEvent(
  3,
  publications[2].comment.commentId,
  publications[2].check.checkRunId,
  "2026-07-21T00:00:05.100Z",
  outputCursorPostComment
);
const outputCursorLogicalScope = {
  installationId: outputCursor.installationId,
  repositoryNodeId: outputCursor.repositoryNodeId,
  pullRequestNodeId: outputCursor.pullRequestNodeId
};
const outputCursorLogicalScopeDigest = digest({
  domain: "pr-output-cursor-scope-v1",
  scope: outputCursorLogicalScope
});
const outputCursorScopeUniquenessReceipt = databaseUniquenessReceipt({
  receiptId: "67676767-1111-4111-8111-111111111111",
  relation: "pr_output_cursor",
  constraintName: "uq_pr_output_cursor_scope",
  key: outputCursorLogicalScope,
  rowIdentity: outputCursor.cursorId,
  transactionId: "67676767-2222-4222-8222-222222222222",
  databaseCommitToken: digest({ fixtureOutputCursorInitializationCommit: 1 }),
  committedAt: outputCursorPre.observedAt
});
const outputCursorHead = {
  schemaVersion: "1.0.0",
  cursorId: outputCursor.cursorId,
  installationId: outputCursor.installationId,
  repositoryNodeId: outputCursor.repositoryNodeId,
  pullRequestNodeId: outputCursor.pullRequestNodeId,
  pullRequestNumber: outputCursor.pullRequestNumber,
  logicalScopeDigest: outputCursorLogicalScopeDigest,
  scopeUniquenessReceipt: outputCursorScopeUniquenessReceipt,
  highWaterCursorRevision: outputCursor.cursorRevision,
  cursorDigest: outputCursor.cursorDigest,
  activeGeneration: outputCursor.activeGeneration,
  activeHeadSha: outputCursor.activeHeadSha,
  databaseSnapshotToken: outputCursor.databaseSnapshotToken,
  serializableReadAt: "2026-07-21T00:00:05.200Z"
};
const deletionOutputCursor = outputCursorEvent(
  4,
  outputCursor.canonicalCommentId,
  outputCursor.canonicalCheckRunId,
  "2026-07-21T00:10:00.800Z",
  outputCursor
);
const deletionOutputCursorHead = {
  ...outputCursorHead,
  highWaterCursorRevision: deletionOutputCursor.cursorRevision,
  cursorDigest: deletionOutputCursor.cursorDigest,
  databaseSnapshotToken: deletionOutputCursor.databaseSnapshotToken,
  serializableReadAt: "2026-07-21T00:10:00.825Z"
};
const commentOwnership = {
  schemaVersion: "1.0.0",
  observationId: "68686868-6868-4868-8868-686868686868",
  installationId: assessment.target.installationId,
  repositoryNodeId: assessment.target.repositoryNodeId,
  pullRequestNodeId: assessment.target.pullRequestNodeId,
  pullRequestNumber: assessment.target.pullRequestNumber,
  commentId: outputCursor.canonicalCommentId,
  markerVersion: "1",
  renderedSourceSetDigest: sourceSetDigest,
  markerDigest: digest({ markerVersion: "1", sourceSetDigest }),
  authorAppId: 424242,
  authorAppSlug: "mergesignal",
  authorInstallationId: assessment.target.installationId,
  ownershipState: "owned",
  providerObservedAt: "2026-07-21T00:00:03.200Z"
};
const deletionCommentOwnership = {
  ...commentOwnership,
  observationId: "69696969-6969-4969-8969-696969696969",
  providerObservedAt: "2026-07-21T00:10:00.850Z"
};
function commentInventory(observationId, matches, providerObservedAt) {
  const core = {
    schemaVersion: "1.0.0",
    observationId,
    installationId: assessment.target.installationId,
    repositoryNodeId: assessment.target.repositoryNodeId,
    pullRequestNodeId: assessment.target.pullRequestNodeId,
    pullRequestNumber: assessment.target.pullRequestNumber,
    authorAppId: 424242,
    authorAppSlug: "mergesignal",
    markerVersion: "1",
    providerTotalCount: matches.length,
    pageInfoComplete: true,
    matches,
    providerObservedAt
  };
  return { ...core, inventoryDigest: digest(core) };
}
const preCommentInventory = commentInventory(
  "77777777-7777-4777-8777-777777777777",
  [],
  "2026-07-21T00:00:01.750Z"
);
const postCommentInventory = commentInventory(
  "78787878-1111-4111-8111-111111111111",
  [{
    commentId: outputCursor.canonicalCommentId,
    ownershipObservationId: commentOwnership.observationId
  }],
  "2026-07-21T00:00:03.300Z"
);
const deletionCommentInventory = commentInventory(
  "79797979-7979-4979-8979-797979797979",
  [{
    commentId: outputCursor.canonicalCommentId,
    ownershipObservationId: deletionCommentOwnership.observationId
  }],
  "2026-07-21T00:10:00.900Z"
);
const outputMutationLeaseCore = {
  schemaVersion: "1.0.0",
  leaseId: "7b7b7b7b-7b7b-4b7b-8b7b-7b7b7b7b7b7b",
  installationId: assessment.target.installationId,
  repositoryNodeId: assessment.target.repositoryNodeId,
  pullRequestNodeId: assessment.target.pullRequestNodeId,
  cursorId: deletionOutputCursor.cursorId,
  cursorRevision: deletionOutputCursor.cursorRevision,
  cursorDigest: deletionOutputCursor.cursorDigest,
  purpose: "terminal_comment_removal",
  fencingToken: 4,
  publicationBlocked: true,
  state: "held",
  databaseSnapshotToken: digest({ fixtureOutputMutationLease: 1 }),
  acquiredAt: "2026-07-21T00:10:00.750Z",
  expiresAt: "2026-07-21T00:10:30.750Z"
};
const outputMutationLease = {
  ...outputMutationLeaseCore,
  leaseDigest: digest(outputMutationLeaseCore)
};
const commentDeletionAuthorityCore = {
  schemaVersion: "1.0.0",
  authorityId: "7a7a7a7a-7a7a-4a7a-8a7a-7a7a7a7a7a7a",
  publicationId: publications[2].publicationId,
  assessmentId: assessment.assessmentId,
  sourceSetDigest,
  mutationLeaseId: outputMutationLease.leaseId,
  mutationLeaseDigest: outputMutationLease.leaseDigest,
  mutationFencingToken: outputMutationLease.fencingToken,
  outputCursorId: deletionOutputCursor.cursorId,
  outputCursorRevision: deletionOutputCursor.cursorRevision,
  outputCursorDigest: deletionOutputCursor.cursorDigest,
  outputCursorSnapshotToken: deletionOutputCursor.databaseSnapshotToken,
  outputCursorReadAt: deletionOutputCursorHead.serializableReadAt,
  commentInventoryObservationId: deletionCommentInventory.observationId,
  commentInventoryDigest: deletionCommentInventory.inventoryDigest,
  authorizedCommentIds: [outputCursor.canonicalCommentId],
  observedAt: deletionCommentInventory.providerObservedAt
};
const commentDeletionAuthority = {
  ...commentDeletionAuthorityCore,
  authorityDigest: digest(commentDeletionAuthorityCore)
};
const retentionHead = lifecycleStreamHead(
  "retention",
  retention.assessmentId,
  [retention],
  "2026-07-21T00:00:05.250Z",
  digest({ fixtureRetentionSnapshot: 3 })
);

function refreshVisibility(record) {
  const cursor = record.phase === "pre_write"
    ? outputCursorPre
    : record.phase === "post_write"
      ? outputCursorPostComment
      : outputCursor;
  const receiptRevision = record.phase === "pre_write" ? 1 : record.phase === "post_write" ? 2 : 3;
  const retentionHeadReadAt = record.phase === "pre_write"
    ? "2026-07-21T00:00:01.900Z"
    : record.phase === "post_write"
      ? "2026-07-21T00:00:03.250Z"
      : retentionHead.serializableReadAt;
  record.expectedSourceSetDigest = sourceSetDigest;
  record.latestObservedHeadSha = assessment.target.headSha;
  record.latestObservedGeneration = assessment.target.generation;
  record.outputCursorId = cursor.cursorId;
  record.outputCursorRevision = cursor.cursorRevision;
  record.outputCursorDigest = cursor.cursorDigest;
  record.outputCursorSnapshotToken = cursor.databaseSnapshotToken;
  record.outputCursorReadAt = cursor.observedAt;
  record.retentionTransitionId = retention.transitionId;
  record.retentionRevision = retention.lifecycleRevision;
  record.retentionState = retention.state;
  record.retentionHeadRevision = retention.lifecycleRevision;
  record.retentionHeadDigest = lifecycleStreamHead(
    "retention",
    retention.assessmentId,
    [retention],
    retentionHeadReadAt,
    digest({ fixtureRetentionSnapshot: receiptRevision })
  ).streamDigest;
  record.retentionSnapshotToken = digest({ fixtureRetentionSnapshot: receiptRevision });
  record.retentionHeadReadAt = retentionHeadReadAt;
  record.publicationAllowed = retention.publicationAllowed;
  record.sources = sourceItems.map((item) => ({
    evidenceId: item.evidenceId,
    expectedVisibility: item.visibility,
    currentVisibility: item.visibility,
    expectedRepositoryNodeId: item.repositoryNodeId ?? null,
    currentRepositoryNodeId: item.repositoryNodeId ?? null,
    expectedRevision: itemRevision(item),
    currentRevision: itemRevision(item),
    visibilityObservedAt: record.observedAt
  }));
  record.visibilityStateDigest = digest(record.sources);
}
refreshVisibility(preVisibility);
refreshVisibility(postVisibility);
refreshVisibility(postCheckVisibility);

for (const publication of publications) {
  const cursor = publication.lifecycleRevision >= 3 ? outputCursor : outputCursorPre;
  const retentionReceiptRevision = publication.lifecycleRevision >= 3 ? 3 : 1;
  publication.renderedSourceSetDigest = sourceSetDigest;
  publication.latestVisibilityStateDigest = postVisibility.visibilityStateDigest;
  publication.policyVersion = assessment.versions.policy;
  publication.policyDigest = assessment.versionDigests.policy;
  publication.engineVersion = assessment.versions.engine;
  publication.engineDigest = assessment.versionDigests.engine;
  publication.outputCursorId = cursor.cursorId;
  publication.outputCursorRevision = cursor.cursorRevision;
  publication.outputCursorDigest = cursor.cursorDigest;
  publication.retentionHeadRevision = retentionHead.highWaterRevision;
  publication.retentionHeadDigest = retentionHead.streamDigest;
  publication.retentionSnapshotToken = digest({ fixtureRetentionSnapshot: retentionReceiptRevision });
  publication.publicationHeadRevision = publication.lifecycleRevision ?? 1;
  publication.publicationHeadDigest = "0".repeat(64);
  publication.publicationSnapshotToken = digest({ fixturePublicationSnapshot: publication.publicationId });
  publication.commentOwnershipObservationId = publication.comment.commentId === null ? null : commentOwnership.observationId;
  publication.commentInventoryObservationId = publication.comment.commentId === null ? null : postCommentInventory.observationId;
  publication.preWriteRetentionTransitionId =
    publication.preWriteRetentionRevision === null ? null : retention.transitionId;
  publication.postWriteRetentionTransitionId =
    publication.postWriteRetentionRevision === null ? null : retention.transitionId;
  publication.postCheckVisibilityValidationId = null;
  publication.postCheckRetentionRevision = null;
  publication.postCheckRetentionTransitionId = null;
  publication.postCheckRetentionState = null;
}

Object.assign(publications[0], {
  transitionId: "31313131-3131-4131-8131-313131313131",
  lifecycleRevision: 1,
  previousState: null,
  state: "queued",
  attemptCount: 0
});
Object.assign(publications[1], {
  publicationId: publications[0].publicationId,
  transitionId: "32323232-3232-4232-8232-323232323232",
  lifecycleRevision: 2,
  previousState: "queued",
  state: "publishing",
  attemptCount: 1,
  createdAt: publications[0].createdAt
});
Object.assign(publications[2], {
  publicationId: publications[0].publicationId,
  transitionId: "33333333-3131-4131-8131-313131313131",
  lifecycleRevision: 3,
  previousState: "publishing",
  state: "published",
  attemptCount: 1,
  createdAt: publications[0].createdAt
});
Object.assign(publications[3], {
  transitionId: "51515151-5151-4151-8151-515151515151",
  lifecycleRevision: 1,
  previousState: null,
  state: "queued",
  attemptCount: 0
});
Object.assign(publications[4], {
  publicationId: publications[3].publicationId,
  transitionId: "52525252-5252-4252-8252-525252525252",
  lifecycleRevision: 2,
  previousState: "queued",
  state: "publishing",
  attemptCount: 1,
  createdAt: publications[3].createdAt
});
Object.assign(publications[5], {
  publicationId: publications[3].publicationId,
  transitionId: "53535353-5353-4353-8353-535353535353",
  lifecycleRevision: 3,
  previousState: "publishing",
  state: "failed",
  attemptCount: 1,
  createdAt: publications[3].createdAt
});
Object.assign(publications[6], {
  transitionId: "41414141-4141-4141-8141-414141414141",
  lifecycleRevision: 1,
  previousState: null,
  state: "queued",
  attemptCount: 0
});
Object.assign(publications[7], {
  publicationId: publications[6].publicationId,
  transitionId: "42424242-4242-4242-8242-424242424242",
  lifecycleRevision: 2,
  previousState: "queued",
  state: "publishing",
  attemptCount: 1,
  createdAt: publications[6].createdAt
});
for (const publishing of [publications[1], publications[4], publications[7]]) {
  publishing.check.checkRunId = null;
}
Object.assign(publications[8], {
  publicationId: publications[6].publicationId,
  transitionId: "43434343-4343-4343-8343-434343434343",
  lifecycleRevision: 3,
  previousState: "publishing",
  state: "stale",
  attemptCount: 1,
  createdAt: publications[6].createdAt
});
Object.assign(publications[9], {
  publicationId: publications[2].publicationId,
  transitionId: "61616161-6161-4161-8161-616161616161",
  lifecycleRevision: 4,
  previousState: "published",
  state: "repair_queued",
  attemptCount: 2,
  generation: publications[2].generation,
  createdAt: publications[2].createdAt,
  updatedAt: "2026-07-21T00:00:06Z"
});
publications[9].check.checkRunId = publications[2].check.checkRunId;
for (const publication of publications) {
  if (publication.check.state === "queued") {
    publication.check.writeStartedAt = null;
    publication.check.writeCompletedAt = null;
  } else {
    publication.check.writeStartedAt = publication.check.lastAttemptAt;
    publication.check.writeCompletedAt = ["completed", "superseded"].includes(publication.check.state)
      ? publication.check.lastAttemptAt
      : null;
  }
}
Object.assign(publications[2], {
  postCheckVisibilityValidationId: postCheckVisibility.validationId,
  latestVisibilityStateDigest: postCheckVisibility.visibilityStateDigest,
  postCheckRetentionRevision: retention.lifecycleRevision,
  postCheckRetentionTransitionId: retention.transitionId,
  postCheckRetentionState: retention.state,
  updatedAt: postCheckVisibility.observedAt
});
Object.assign(publications[2].check, {
  lastAttemptAt: "2026-07-21T00:00:05Z",
  writeStartedAt: "2026-07-21T00:00:04.500Z",
  writeCompletedAt: "2026-07-21T00:00:05Z"
});
const publicationStreams = Map.groupBy(publications, (event) => event.publicationId);
for (const stream of publicationStreams.values()) {
  const ordered = [...stream].sort((left, right) => left.lifecycleRevision - right.lifecycleRevision);
  for (const event of ordered) {
    const prefix = ordered.filter((candidate) => candidate.lifecycleRevision <= event.lifecycleRevision);
    const head = lifecycleStreamHead(
      "publication",
      event.publicationId,
      prefix,
      event.updatedAt,
      event.publicationSnapshotToken
    );
    event.publicationHeadRevision = head.highWaterRevision;
    event.publicationHeadDigest = head.streamDigest;
  }
}
const publicationHead = lifecycleStreamHead(
  "publication",
  publications[2].publicationId,
  publications.slice(0, 3),
  publications[2].updatedAt,
  publications[2].publicationSnapshotToken
);
const commentRemovals = await Promise.all(commentRemovalPaths.map(readJson));
const terminalRetentionTransactionId = "81818181-8181-4181-8181-818181818181";
const terminalRetentionCommitToken = digest({ fixtureTerminalRetentionCommit: 1 });
const terminalRetentionOutboxBatchId = "82828282-8282-4282-8282-828282828282";
const removalTransactionIds = [
  "87878787-1111-4111-8111-111111111111",
  "83838383-8383-4383-8383-838383838383",
  "84848484-8484-4484-8484-848484848484"
];
const removalOutboxBatchIds = [
  "87878787-2222-4222-8222-222222222222",
  "85858585-8585-4585-8585-858585858585",
  "86868686-8686-4686-8686-868686868686"
];
for (const [index, removal] of commentRemovals.entries()) Object.assign(removal, {
  commentOwnershipObservationId: deletionCommentOwnership.observationId,
  deletionAuthorityId: commentDeletionAuthority.authorityId,
  deletionAuthorityDigest: commentDeletionAuthority.authorityDigest,
  outputCursorRevision: commentDeletionAuthority.outputCursorRevision,
  outputCursorDigest: commentDeletionAuthority.outputCursorDigest,
  commentInventoryObservationId: commentDeletionAuthority.commentInventoryObservationId,
  commentInventoryDigest: commentDeletionAuthority.commentInventoryDigest,
  originTransactionId: terminalRetentionTransactionId,
  originDatabaseCommitToken: terminalRetentionCommitToken,
  originOutboxBatchId: terminalRetentionOutboxBatchId,
  transactionId: removalTransactionIds[index],
  databaseCommitToken: digest({ fixtureCommentRemovalCommit: index + 1 }),
  outboxBatchId: removalOutboxBatchIds[index]
});
const commentRemovalHead = lifecycleStreamHead(
  "comment_removal",
  commentRemovals[0].removalId,
  commentRemovals,
  commentRemovals.at(-1).updatedAt,
  digest({ fixtureCommentRemovalSnapshot: 1 })
);
const assessmentDigest = digest(assessment);
const dashboardPolicyRevisions = manifest.items
  .filter((item) =>
    item.type === "DASHBOARD_POLICY_REVISION" &&
    item.canonicalPayload.installationId === assessment.target.installationId &&
    item.canonicalPayload.repositoryNodeId === assessment.target.repositoryNodeId
  )
  .sort((left, right) => left.canonicalPayload.revisionSequence - right.canonicalPayload.revisionSequence);
const dashboardPolicyHeadEvidence = manifest.items.find((item) => item.evidenceId === "ev_policy_head");
const detailedPermissionObservationCore = {
  observationId: "74747474-7474-4474-8474-747474747474",
  providerRequestId: "75757575-7575-4575-8575-757575757575",
  providerResponseId: "github-request-fixture-detailed-report-1",
  viewerGithubNodeId: "U_maintainer_admin",
  installationId: assessment.target.installationId,
  repositoryNodeId: assessment.target.repositoryNodeId,
  permission: "admin",
  providerObservedAt: "2026-07-21T00:00:01Z"
};
const detailedPermissionObservation = {
  ...detailedPermissionObservationCore,
  observationDigest: digest(detailedPermissionObservationCore)
};
const detailedPolicyHeadCore = {
  deploymentId: "kontext-production",
  installationId: assessment.target.installationId,
  repositoryNodeId: assessment.target.repositoryNodeId,
  logicalStreamKeyDigest: digest({
    domain: "dashboard-policy-stream-v1",
    deploymentId: "kontext-production",
    installationId: assessment.target.installationId,
    repositoryNodeId: assessment.target.repositoryNodeId
  }),
  streamId: dashboardPolicyHeadEvidence.canonicalPayload.streamId,
  highWaterRevision: dashboardPolicyRevisions.at(-1).canonicalPayload.revisionSequence,
  highWaterRevisionId: dashboardPolicyRevisions.at(-1).canonicalPayload.revisionId,
  streamDigest: digest(dashboardPolicyRevisions.map((item) => item.canonicalPayload)),
  databaseSnapshotToken: digest({ fixtureDetailedReportSnapshot: 1 }),
  serializableReadAt: "2026-07-21T00:00:01.050Z"
};
const detailedPolicyHead = {
  ...detailedPolicyHeadCore,
  headDigest: digest(detailedPolicyHeadCore)
};
const detailedReportAuthorityCore = {
  schemaVersion: "1.0.0",
  authorityId: "76767676-7676-4676-8676-767676767676",
  sessionId: "70707070-7070-4070-8070-707070707070",
  requestNonce: "72727272-7272-4272-8272-727272727272",
  viewerGithubNodeId: detailedPermissionObservation.viewerGithubNodeId,
  installationId: assessment.target.installationId,
  repositoryNodeId: assessment.target.repositoryNodeId,
  permissionObservation: detailedPermissionObservation,
  policyHead: detailedPolicyHead,
  receivedAt: "2026-07-21T00:00:01.075Z"
};
const detailedReportAuthority = {
  ...detailedReportAuthorityCore,
  authorityDigest: digest(detailedReportAuthorityCore)
};
const detailedReportAuthorizationId = "71717171-7171-4171-8171-717171717171";
const detailedReportNonceTransactionId = "71717171-2222-4222-8222-222222222222";
const detailedReportNonceCommitToken = digest({ fixtureDetailedReportNonceCommit: 1 });
const detailedReportNonceUniquenessReceipt = databaseUniquenessReceipt({
  receiptId: "71717171-3333-4333-8333-333333333333",
  relation: "detailed_report_nonce_consumption",
  constraintName: "uq_detailed_report_session_nonce",
  key: {
    sessionId: detailedReportAuthority.sessionId,
    requestNonce: detailedReportAuthority.requestNonce
  },
  rowIdentity: "71717171-4444-4444-8444-444444444444",
  transactionId: detailedReportNonceTransactionId,
  databaseCommitToken: detailedReportNonceCommitToken,
  committedAt: "2026-07-21T00:00:01.100Z"
});
const detailedReportNonceConsumptionCore = {
  schemaVersion: "1.0.0",
  consumptionId: detailedReportNonceUniquenessReceipt.rowIdentity,
  authorizationId: detailedReportAuthorizationId,
  sessionId: detailedReportAuthority.sessionId,
  requestNonce: detailedReportAuthority.requestNonce,
  viewerGithubNodeId: detailedReportAuthority.viewerGithubNodeId,
  installationId: assessment.target.installationId,
  repositoryNodeId: assessment.target.repositoryNodeId,
  assessmentId: assessment.assessmentId,
  uniquenessReceipt: detailedReportNonceUniquenessReceipt,
  consumedAt: detailedReportNonceUniquenessReceipt.committedAt
};
const detailedReportNonceConsumption = {
  ...detailedReportNonceConsumptionCore,
  consumptionDigest: digest(detailedReportNonceConsumptionCore)
};
const detailedReportAuthorizationCore = {
  schemaVersion: "1.0.0",
  authorizationId: detailedReportAuthorizationId,
  authorityId: detailedReportAuthority.authorityId,
  sessionId: detailedReportAuthority.sessionId,
  requestNonce: detailedReportAuthority.requestNonce,
  viewerGithubNodeId: "U_maintainer_admin",
  installationId: assessment.target.installationId,
  repositoryNodeId: assessment.target.repositoryNodeId,
  repositoryPermission: "admin",
  assessmentId: assessment.assessmentId,
  assessmentDigest,
  permissionObservationId: detailedPermissionObservation.observationId,
  permissionObservationDigest: detailedPermissionObservation.observationDigest,
  policyStreamId: detailedPolicyHead.streamId,
  policyHeadRevision: detailedPolicyHead.highWaterRevision,
  policyHeadRevisionId: detailedPolicyHead.highWaterRevisionId,
  policyHeadDigest: detailedPolicyHead.streamDigest,
  databaseSnapshotToken: detailedPolicyHead.databaseSnapshotToken,
  policyHeadReadAt: detailedPolicyHead.serializableReadAt,
  authorizedAt: "2026-07-21T00:00:01.100Z",
  expiresAt: "2026-07-21T00:05:01.100Z",
  nonceConsumptionId: detailedReportNonceConsumption.consumptionId,
  nonceConsumptionDigest: detailedReportNonceConsumption.consumptionDigest,
  nonceConsumptionCommitToken: detailedReportNonceUniquenessReceipt.databaseCommitToken
};
const detailedReportAuthorization = {
  ...detailedReportAuthorizationCore,
  authorizationDigest: digest(detailedReportAuthorizationCore)
};
const detailedReportCoverage = byId.get(
  assessment.coverage.evidenceIds[0]
).canonicalPayload;
const detailedReportProjectionCore = {
  schemaVersion: "1.0.0",
  reportId: "73737373-7373-4373-8373-737373737373",
  assessmentId: assessment.assessmentId,
  assessmentDigest,
  authorizationId: detailedReportAuthorization.authorizationId,
  contributor: {
    availability: assessment.subject.availability,
    loginAtAssessment: assessment.subject.loginAtAssessment,
    actorType: assessment.subject.actorType,
    historySupport: assessment.subject.historySupport
  },
  target: {
    repositoryNodeId: assessment.target.repositoryNodeId,
    pullRequestNumber: assessment.target.pullRequestNumber,
    headSha: assessment.target.headSha,
    generation: assessment.target.generation
  },
  summaryState: assessment.summaryState,
  overallConfidence: structuredClone(assessment.overallConfidence),
  reviewPriority: assessment.reviewPriority,
  dimensions: Object.fromEntries(Object.entries(assessment.dimensions).map(([name, dimension]) => [name, {
    score: dimension.score,
    confidence: dimension.confidence,
    state: dimension.state,
    reasonCodes: structuredClone(dimension.reasonCodes),
    evidenceCount: dimension.evidenceIds.length
  }])),
  coverage: {
    requestedWindowYears: assessment.coverage.requestedWindowYears,
    completeYears: assessment.coverage.completeYears,
    freshAsOf: assessment.coverage.freshAsOf,
    freshness: detailedReportCoverage.freshness,
    attribution: detailedReportCoverage.attribution,
    confidence: assessment.coverage.confidence,
    reasonCodes: structuredClone(assessment.coverage.reasonCodes)
  },
  generatedAt: "2026-07-21T00:00:01.200Z"
};
const detailedReportProjection = {
  ...detailedReportProjectionCore,
  projectionDigest: digest(detailedReportProjectionCore)
};
const githubAppIdentityObservationCore = {
  schemaVersion: "1.0.0",
  observationId: "91919191-9191-4191-8191-919191919191",
  deploymentId: "kontext-production",
  credentialFingerprint: digest({ fixtureCredentialPublicKey: "mergesignal-production-v1" }),
  providerRequestId: "92929292-9292-4292-8292-929292929292",
  providerResponseId: "github-request-fixture-app-identity-1",
  appId: 424242,
  slug: "mergesignal",
  providerObservedAt: "2026-07-21T00:00:00.500Z"
};
const githubAppIdentityObservation = {
  ...githubAppIdentityObservationCore,
  observationDigest: digest(githubAppIdentityObservationCore)
};
await Promise.all([
  writeJson(manifestPath, manifest),
  writeJson(assessmentPath, assessment),
  writeJson("contracts/examples/assessment-retention-state.json", retention),
  writeJson(publicCommentPath, publicComment),
  writeJson(privateCommentPath, privateComment),
  writeJson(preVisibilityPath, preVisibility),
  writeJson(postVisibilityPath, postVisibility),
  writeJson(postCheckVisibilityPath, postCheckVisibility),
  writeJson(outputCursorPath, outputCursor),
  writeJson(outputCursorPrePath, outputCursorPre),
  writeJson(outputCursorPostCommentPath, outputCursorPostComment),
  writeJson(outputCursorHeadPath, outputCursorHead),
  writeJson(deletionOutputCursorPath, deletionOutputCursor),
  writeJson(deletionOutputCursorHeadPath, deletionOutputCursorHead),
  writeJson(commentOwnershipPath, commentOwnership),
  writeJson(deletionCommentOwnershipPath, deletionCommentOwnership),
  writeJson(preCommentInventoryPath, preCommentInventory),
  writeJson(postCommentInventoryPath, postCommentInventory),
  writeJson(deletionCommentInventoryPath, deletionCommentInventory),
  writeJson(commentDeletionAuthorityPath, commentDeletionAuthority),
  writeJson(outputMutationLeasePath, outputMutationLease),
  writeJson(retentionStreamHeadPath, retentionHead),
  writeJson(publicationStreamHeadPath, publicationHead),
  writeJson(commentRemovalStreamHeadPath, commentRemovalHead),
  writeJson(detailedReportAuthorityPath, detailedReportAuthority),
  writeJson(detailedReportNonceConsumptionPath, detailedReportNonceConsumption),
  writeJson(detailedReportAuthorizationPath, detailedReportAuthorization),
  writeJson(detailedReportProjectionPath, detailedReportProjection),
  writeJson(githubAppIdentityObservationPath, githubAppIdentityObservation),
  ...commentRemovalPaths.map((path, index) => writeJson(path, commentRemovals[index])),
  ...publicationPaths.map((path, index) => writeJson(path, publications[index]))
]);

for (const [relativePath, generated] of stagedWrites) {
  const absolutePath = resolve(root, relativePath);
  if (checkMode) {
    const current = await readFile(absolutePath, "utf8");
    if (current !== generated) throw new Error(`Generated Phase 0 artifact is stale: ${relativePath}`);
  } else {
    await writeFile(absolutePath, generated);
  }
}

console.log(`${checkMode ? "Verified" : "Refreshed"} Phase 0 examples: manifest=${assessment.evidenceSnapshot.canonicalHash} sourceSet=${sourceSetDigest}`);
