import { createHash } from "node:crypto";

import {
  canonicalizeIJson as canonicalize,
  canonicalDigest,
  parseMergeSignalYaml
} from "../runtime/replay-runtime-v1.mjs";
import { evaluateReasonPredicate as evaluateVersionedReasonPredicate } from "./feature-evaluator-v1.mjs";

export const assessmentEngineContractVersion = "assessment-engine-v2";

export const contextualizationDimensionOrder = Object.freeze([
  "tenure_continuity",
  "independent_open_source_record",
  "merge_follow_through",
  "collaboration",
  "relevant_experience",
  "integrity_gaming_resistance"
]);

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function jsonEquals(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function pullRequestIdentity(item) {
  const payload = item.canonicalPayload;
  if (!payload.pullRequestNodeId) return null;
  return {
    pullRequestNodeId: payload.pullRequestNodeId,
    repositoryNodeId: payload.repositoryNodeId ?? item.repositoryNodeId ?? null,
    pullRequestNumber: payload.pullRequestNumber ?? null,
    authorNodeId: payload.authorNodeId ?? payload.pullRequestAuthorNodeId ?? null
  };
}

function samePullRequestIdentity(left, right) {
  const a = pullRequestIdentity(left);
  const b = pullRequestIdentity(right);
  if (!a || !b) return false;
  return a.pullRequestNodeId === b.pullRequestNodeId &&
    a.repositoryNodeId === b.repositoryNodeId &&
    a.pullRequestNumber === b.pullRequestNumber &&
    (a.authorNodeId === null || b.authorNodeId === null || a.authorNodeId === b.authorNodeId);
}

function normalizePathFamily(path) {
  const withoutExtension = path.toLowerCase().replace(/\.(?:test|spec)(?=\.[^/.]+$)/, "").replace(/\.[^/.]+$/, "");
  return withoutExtension.split("/").filter((part) => !["src", "test", "tests", "__tests__"].includes(part)).join("/");
}

function monthOffset(yearMonth, offset) {
  const [year, month] = yearMonth.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1 + offset, 1));
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
}

function activeMonthWindowCounts(inputs, windowEndMonth) {
  const months = new Set(inputs.filter((input) => input.type === "ACTIVE_MONTH").map((input) => input.canonicalPayload.yearMonth));
  const recent = new Set(Array.from({ length: 3 }, (_, index) => monthOffset(windowEndMonth, -index)));
  const baseline = new Set(Array.from({ length: 12 }, (_, index) => monthOffset(windowEndMonth, -(index + 3))));
  return {
    recentActiveMonths: [...recent].filter((month) => months.has(month)).length,
    baselineActiveMonths: [...baseline].filter((month) => months.has(month)).length
  };
}

export function validateDerivedEvidence({ item, inputs, predicate, features, assert, assertNoDuplicateJsonMembers }) {
  const payload = item.canonicalPayload;
  const ofType = (type) => inputs.filter((input) => input.type === type);
  switch (predicate) {
    case "active_month_v1":
      assert(
        ofType("CONTRIBUTION_YEAR").some((input) =>
          input.canonicalPayload.activeMonths.includes(payload.yearMonth)
        ),
        `Active month ${item.evidenceId} is not present in its source year`
      );
      return;
    case "repository_ownership_v1": {
      const opened = ofType("PULL_REQUEST_OPENED")[0];
      const merged = ofType("PULL_REQUEST_MERGED")[0];
      const mergeActor = ofType("MERGE_ACTOR")[0];
      assert(opened && merged && mergeActor, `Ownership derivation ${item.evidenceId} lacks source facts`);
      assert(
        [opened, merged, mergeActor].every((input) => samePullRequestIdentity(opened, input)),
        `Ownership derivation ${item.evidenceId} combines different pull requests`
      );
      assert(payload.pullRequestNodeId === opened.canonicalPayload.pullRequestNodeId, "Ownership PR mismatch");
      assert(payload.repositoryNodeId === opened.canonicalPayload.repositoryNodeId, "Ownership repository mismatch");
      assert(payload.pullRequestNumber === opened.canonicalPayload.pullRequestNumber, "Ownership PR number mismatch");
      assert(payload.subjectNodeId === opened.canonicalPayload.authorNodeId, "Ownership subject mismatch");
      assert(payload.repositoryOwnerNodeId === opened.canonicalPayload.repositoryOwnerNodeId, "Ownership owner mismatch");
      const expected =
        opened.canonicalPayload.repositoryOwnerNodeId === payload.subjectNodeId ||
        opened.canonicalPayload.authorAssociation === "OWNER" ||
        mergeActor.canonicalPayload.githubNodeId === payload.subjectNodeId
          ? "self_controlled"
          : ["MEMBER", "COLLABORATOR"].includes(opened.canonicalPayload.authorAssociation)
            ? "affiliated"
            : ["CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "NONE"].includes(
                  opened.canonicalPayload.authorAssociation
                ) && mergeActor.canonicalPayload.githubNodeId !== payload.subjectNodeId
              ? "independently_maintained"
              : "unknown";
      assert(payload.classification === expected, "Ownership classification is not deterministic");
      return;
    }
    case "dependency_ecosystem_v1": {
      const manifests = new Map([
        ["package.json", "npm"],
        ["pnpm-lock.yaml", "npm"],
        ["yarn.lock", "npm"],
        ["cargo.toml", "cargo"],
        ["pyproject.toml", "python"],
        ["requirements.txt", "python"],
        ["go.mod", "go"],
        ["pom.xml", "maven"],
        ["build.gradle", "gradle"]
      ]);
      const path = ofType("CHANGED_PATH").find(
        (input) => input.canonicalPayload.path === payload.manifestPath
      );
      assert(path, `Dependency ecosystem ${item.evidenceId} lacks its manifest path`);
      assert(payload.repositoryNodeId === path.canonicalPayload.repositoryNodeId, "Dependency repository mismatch");
      const file = payload.manifestPath.toLowerCase().split("/").at(-1);
      assert(manifests.get(file) === payload.ecosystem.toLowerCase(), "Dependency ecosystem mismatch");
      return;
    }
    case "activity_burst_v1":
    case "behavior_baseline_v1": {
      const counts = activeMonthWindowCounts(inputs, payload.windowEndMonth);
      assert(
        counts.baselineActiveMonths >= 1,
        `${predicate} requires an observed non-zero historical baseline instead of inventing a denominator`
      );
      assert(payload.recentActiveMonths === counts.recentActiveMonths, "Recent active-month count mismatch");
      assert(payload.baselineActiveMonths === counts.baselineActiveMonths, "Baseline active-month count mismatch");
      const recentRate = counts.recentActiveMonths / 3;
      const baselineRate = counts.baselineActiveMonths / 12;
      const derivedRatio = recentRate / baselineRate;
      const field = predicate === "activity_burst_v1" ? "ratio" : "relativeIncrease";
      assert(Math.abs(payload[field] - derivedRatio) < 1e-12, `${field} mismatch`);
      return;
    }
    case "template_similarity_v1": {
      const ownership = ofType("REPOSITORY_OWNERSHIP_RELATIONSHIP");
      const eligible = ofType("PULL_REQUEST_OPENED").filter(
        (input) =>
          input.canonicalPayload.informativeFeatureCount >= 3 &&
          ownership.some(
            (relationship) =>
              relationship.canonicalPayload.pullRequestNodeId ===
                input.canonicalPayload.pullRequestNodeId &&
              relationship.canonicalPayload.classification === "independently_maintained"
          )
      );
      const repositories = new Set(eligible.map((input) => input.canonicalPayload.repositoryNodeId));
      assert(repositories.size === eligible.length, "Template similarity repeats a repository");
      const fingerprints = eligible.map(
        (input) => input.canonicalPayload.templateAdjustedFingerprint
      );
      assert(fingerprints.length >= 5, "Template similarity lacks five informative unrelated contributions");
      const counts = new Map();
      for (const fingerprint of fingerprints) counts.set(fingerprint, (counts.get(fingerprint) ?? 0) + 1);
      const [dominantFingerprint, matchingCount] = [...counts.entries()].sort(
        (left, right) => right[1] - left[1] || compareUtf8(left[0], right[0])
      )[0];
      assert(payload.sampleSize === fingerprints.length, "Template sample-size mismatch");
      assert(payload.repositoryCount === repositories.size, "Template repository-count mismatch");
      assert(payload.dominantFingerprint === dominantFingerprint, "Template fingerprint mismatch");
      assert(payload.matchingCount === matchingCount, "Template matching-count mismatch");
      assert(Math.abs(payload.similarity - matchingCount / fingerprints.length) < 1e-12, "Template similarity mismatch");
      return;
    }
    case "reciprocal_merge_v1": {
      const events = ofType("MERGE_RELATIONSHIP_EVENT");
      const relevant = events.filter((event) => {
        const value = event.canonicalPayload;
        return (
          (value.authorNodeId === payload.subjectNodeId && value.mergeActorNodeId === payload.counterpartyNodeId) ||
          (value.authorNodeId === payload.counterpartyNodeId && value.mergeActorNodeId === payload.subjectNodeId)
        );
      });
      const outgoing = relevant.filter((event) => event.canonicalPayload.authorNodeId === payload.subjectNodeId).length;
      const incoming = relevant.length - outgoing;
      const reciprocalCount = 2 * Math.min(outgoing, incoming);
      assert(payload.mergeCount === relevant.length, "Reciprocal merge-count mismatch");
      assert(payload.reciprocalCount === reciprocalCount, "Reciprocal count mismatch");
      assert(Math.abs(payload.ratio - reciprocalCount / relevant.length) < 1e-12, "Reciprocal ratio mismatch");
      return;
    }
    case "relevance_comparison_v1": {
      const historicalPr = ofType("PULL_REQUEST_OPENED").find(
        (input) => input.canonicalPayload.pullRequestNodeId === payload.historicalPullRequestNodeId
      );
      assert(historicalPr, "Relevance comparison lacks its historical pull request");
      assert(
        historicalPr.canonicalPayload.repositoryNodeId === payload.historicalRepositoryNodeId,
        "Relevance historical repository mismatch"
      );
      assert(
        payload.historicalPullRequestNodeId !== payload.targetPullRequestNodeId,
        "Relevance comparison cannot compare the target pull request with itself"
      );
      const historicalFileset = inputs.find(
        (input) => input.evidenceId === payload.historicalFilesetEvidenceId && input.type === "PATCH_FILESET_STATUS"
      );
      const targetFileset = inputs.find(
        (input) => input.evidenceId === payload.targetFilesetEvidenceId && input.type === "PATCH_FILESET_STATUS"
      );
      assert(historicalFileset && targetFileset, "Relevance comparison lacks its explicit filesets");
      assert(
        historicalFileset.canonicalPayload.pullRequestNodeId === payload.historicalPullRequestNodeId &&
          historicalFileset.canonicalPayload.repositoryNodeId === payload.historicalRepositoryNodeId &&
          historicalFileset.canonicalPayload.headSha === payload.historicalHeadSha &&
          historicalFileset.canonicalPayload.complete,
        "Relevance historical fileset is not complete and revision-bound"
      );
      assert(
        targetFileset.canonicalPayload.pullRequestNodeId === payload.targetPullRequestNodeId &&
          targetFileset.canonicalPayload.repositoryNodeId === payload.targetRepositoryNodeId &&
          targetFileset.canonicalPayload.headSha === payload.targetHeadSha &&
          targetFileset.canonicalPayload.complete,
        "Relevance target fileset is not complete and head-bound"
      );
      const domainsFor = (repositoryNodeId) =>
        new Set(
          [...ofType("REPOSITORY_TOPIC"), ...ofType("DEPENDENCY_ECOSYSTEM")]
            .filter((input) => input.canonicalPayload.repositoryNodeId === repositoryNodeId)
            .map((input) => (input.canonicalPayload.topic ?? input.canonicalPayload.ecosystem).toLowerCase())
        );
      const historicalDomains = domainsFor(payload.historicalRepositoryNodeId);
      const targetDomains = domainsFor(payload.targetRepositoryNodeId);
      const domainMatches = [...historicalDomains].filter((value) => targetDomains.has(value)).sort(compareUtf8);
      assert(jsonEquals(payload.domainMatches, domainMatches), "Relevance domain comparison mismatch");
      const historicalPaths = ofType("CHANGED_PATH").filter(
        (input) =>
          input.canonicalPayload.pullRequestNodeId === payload.historicalPullRequestNodeId &&
          input.canonicalPayload.repositoryNodeId === payload.historicalRepositoryNodeId &&
          input.canonicalPayload.headSha === payload.historicalHeadSha
      );
      const targetPaths = ofType("CHANGED_PATH").filter(
        (input) =>
          input.canonicalPayload.pullRequestNodeId === payload.targetPullRequestNodeId &&
          input.canonicalPayload.repositoryNodeId === payload.targetRepositoryNodeId &&
          input.canonicalPayload.headSha === payload.targetHeadSha
      );
      assert(
        historicalFileset.canonicalPayload.collectedFileCount === historicalPaths.length &&
          targetFileset.canonicalPayload.collectedFileCount === targetPaths.length,
        "Relevance fileset counts do not match the revision-bound paths"
      );
      assert(
        [...historicalPaths, ...targetPaths].every(
          (path) => path.canonicalPayload.languageFeatureVersion === "path-language-v1"
        ),
        "Relevance paths use an unsupported language feature"
      );
      const historicalLanguages = new Set(
        historicalPaths.map((path) => path.canonicalPayload.language).filter(Boolean)
      );
      const targetLanguages = new Set(
        targetPaths.map((path) => path.canonicalPayload.language).filter(Boolean)
      );
      const languageMatches = [...historicalLanguages]
        .filter((value) => targetLanguages.has(value))
        .sort(compareUtf8);
      assert(
        jsonEquals(payload.languageMatches, languageMatches),
        "Relevance language comparison is not bound to contributed paths"
      );
      const pathMatches = historicalPaths
        .flatMap((historical) =>
          targetPaths
            .filter(
              (targetPath) =>
                normalizePathFamily(historical.canonicalPayload.path) ===
                normalizePathFamily(targetPath.canonicalPayload.path)
            )
            .map((targetPath) => ({
              historicalPath: historical.canonicalPayload.path,
              targetPath: targetPath.canonicalPayload.path,
              pathFamily: normalizePathFamily(historical.canonicalPayload.path)
            }))
        )
        .sort((left, right) => compareUtf8(canonicalize(left), canonicalize(right)));
      assert(jsonEquals(payload.pathMatches, pathMatches), "Relevance path comparison mismatch");
      return;
    }
    case "patch_scope_v1": {
      const paths = ofType("CHANGED_PATH");
      const ci = ofType("CI_CHECK_STATE")[0];
      const fileset = ofType("PATCH_FILESET_STATUS")[0];
      assert(ci && fileset, `Patch scope ${item.evidenceId} lacks source facts`);
      assert(paths.every((path) => samePullRequestIdentity(path, ci)), "Patch scope combines pull requests");
      assert(samePullRequestIdentity(ci, fileset), "Patch scope fileset targets another pull request");
      assert(ci.canonicalPayload.headSha === fileset.canonicalPayload.headSha, "Patch scope CI and fileset heads differ");
      assert(
        paths.every((path) => path.canonicalPayload.headSha === fileset.canonicalPayload.headSha),
        "Patch scope includes paths from another head"
      );
      assert(fileset.canonicalPayload.collectedFileCount === paths.length, "Fileset collected count disagrees with paths");
      for (const key of ["pullRequestNodeId", "repositoryNodeId", "pullRequestNumber", "headSha"]) {
        assert(payload[key] === fileset.canonicalPayload[key], `Patch scope ${key} mismatch`);
      }
      assert(payload.filesetComplete === fileset.canonicalPayload.complete, "Patch scope completeness mismatch");
      assert(payload.filesChanged === paths.length, "Patch scope file count mismatch");
      assert(payload.additions === paths.reduce((total, input) => total + input.canonicalPayload.additions, 0), "Patch scope additions mismatch");
      assert(payload.deletions === paths.reduce((total, input) => total + input.canonicalPayload.deletions, 0), "Patch scope deletions mismatch");
      const linesChanged = payload.additions + payload.deletions;
      const expected = !payload.filesetComplete
        ? "unknown"
        : payload.filesChanged <= 3 && linesChanged <= 20
          ? "small"
          : payload.filesChanged <= 20 && linesChanged <= 500
            ? "medium"
            : "large";
      assert(payload.classification === expected, "Patch scope classification mismatch");
      return;
    }
    case "test_path_change_v1": {
      const paths = ofType("CHANGED_PATH");
      const ci = ofType("CI_CHECK_STATE")[0];
      const fileset = ofType("PATCH_FILESET_STATUS")[0];
      assert(ci && fileset && samePullRequestIdentity(ci, fileset), "Test-path source identity mismatch");
      assert(paths.every((path) => samePullRequestIdentity(path, ci)), "Test-path inputs cross pull requests");
      assert(ci.canonicalPayload.headSha === fileset.canonicalPayload.headSha, "Test-path CI and fileset heads differ");
      assert(paths.every((path) => path.canonicalPayload.headSha === fileset.canonicalPayload.headSha), "Test-path inputs cross heads");
      assert(fileset.canonicalPayload.collectedFileCount === paths.length, "Test-path fileset count mismatch");
      const changed = paths.some((input) =>
        /(^|\/)(?:test|tests|__tests__)(\/|$)|\.(?:test|spec)\.[^/]+$/i.test(input.canonicalPayload.path)
      );
      const state = fileset.canonicalPayload.complete ? (changed ? "changed" : "unchanged") : "unknown";
      assert(payload.pullRequestNodeId === fileset.canonicalPayload.pullRequestNodeId, "Test-path PR mismatch");
      assert(payload.repositoryNodeId === fileset.canonicalPayload.repositoryNodeId, "Test-path repository mismatch");
      assert(payload.pullRequestNumber === fileset.canonicalPayload.pullRequestNumber, "Test-path number mismatch");
      assert(payload.headSha === fileset.canonicalPayload.headSha, "Test-path head mismatch");
      assert(payload.filesetComplete === fileset.canonicalPayload.complete, "Test-path completeness mismatch");
      assert(payload.state === state, "Test-path classification mismatch");
      return;
    }
    case "repository_risk_policy_v1": {
      const normalizedConfiguration = {
        reviewPriorityEnabled: payload.reviewPriorityEnabled,
        rules: payload.rules
      };
      const normalizedConfigurationBytes = Buffer.from(canonicalize(normalizedConfiguration), "utf8");
      const configurationDigest = createHash("sha256").update(normalizedConfigurationBytes).digest("hex");
      if (payload.configurationSource.kind === "dashboard_revision") {
        const revision = ofType("DASHBOARD_POLICY_REVISION").find(
          (candidate) => candidate.evidenceId === payload.configurationSource.revisionEvidenceId
        );
        const permission = ofType("REPOSITORY_ADMIN_PERMISSION").find(
          (candidate) => candidate.evidenceId === payload.configurationSource.adminPermissionEvidenceId
        );
        const policyHead = ofType("DASHBOARD_POLICY_STREAM_HEAD").find(
          (candidate) => candidate.evidenceId === payload.configurationSource.policyHeadEvidenceId
        );
        assert(revision && permission && policyHead, `Dashboard policy ${item.evidenceId} lacks provider-backed authorization`);
        assert(
          payload.configurationSource.revisionEvidenceId === revision.evidenceId &&
            payload.configurationSource.adminPermissionEvidenceId === permission.evidenceId,
          `Dashboard policy ${item.evidenceId} does not bind its exact provenance records`
        );
        assert(
          [revision, permission, policyHead].every((input) =>
            input.canonicalPayload.installationId === payload.installationId &&
            input.canonicalPayload.repositoryNodeId === payload.repositoryNodeId
          ),
          `Dashboard policy ${item.evidenceId} provenance crosses installation or repository scope`
        );
        assert(
          permission.canonicalPayload.permission === "admin" &&
            permission.canonicalPayload.state === "granted" &&
            permission.canonicalPayload.actorGithubNodeId === revision.canonicalPayload.actorGithubNodeId &&
            permission.canonicalPayload.authorizationForRevisionId === revision.canonicalPayload.revisionId &&
            permission.canonicalPayload.authorizationForRevisionSequence === revision.canonicalPayload.revisionSequence &&
            permission.canonicalPayload.authorizationHeadRevision === revision.canonicalPayload.authorizedHeadRevision &&
            revision.canonicalPayload.revisionSequence === revision.canonicalPayload.authorizedHeadRevision &&
            permission.canonicalPayload.authorizationNonce === revision.canonicalPayload.authorizationNonce &&
            permission.canonicalPayload.authorizationSnapshotToken === revision.canonicalPayload.authorizationSnapshotToken &&
            permission.canonicalPayload.providerObservedAt === permission.observedAt,
          `Dashboard policy ${item.evidenceId} lacks exact admin authorization`
        );
        assert(
          revision.canonicalPayload.configurationDigest === configurationDigest,
          `Dashboard policy ${item.evidenceId} configuration digest differs from its revision`
        );
        assert(
          permission.observedAt === revision.canonicalPayload.recordedAt &&
            new Date(revision.canonicalPayload.recordedAt) <= new Date(payload.effectiveFrom),
          `Dashboard policy ${item.evidenceId} authorization is not atomically bound to activation`
        );
        assert(
          new Date(payload.effectiveFrom) - new Date(permission.canonicalPayload.providerObservedAt) <=
            features.dashboardAuthorization.maxAgeSeconds * 1000,
          `Dashboard policy ${item.evidenceId} uses stale administrator authorization`
        );
        const revisions = ofType("DASHBOARD_POLICY_REVISION")
          .filter((candidate) =>
            candidate.canonicalPayload.installationId === payload.installationId &&
            candidate.canonicalPayload.repositoryNodeId === payload.repositoryNodeId
          )
          .sort((left, right) => left.canonicalPayload.revisionSequence - right.canonicalPayload.revisionSequence);
        assert(
          revisions.at(-1)?.evidenceId === revision.evidenceId &&
            policyHead.canonicalPayload.highWaterRevision === revision.canonicalPayload.revisionSequence &&
            policyHead.canonicalPayload.highWaterRevisionId === revision.canonicalPayload.revisionId &&
            policyHead.canonicalPayload.streamDigest === createHash("sha256").update(canonicalize(revisions.map((candidate) => candidate.canonicalPayload)), "utf8").digest("hex") &&
            policyHead.canonicalPayload.databaseSnapshotToken === revision.canonicalPayload.authorizationSnapshotToken &&
            policyHead.canonicalPayload.serializableReadAt === policyHead.observedAt,
          `Dashboard policy ${item.evidenceId} is not based on an independently observed complete revision stream`
        );
        assert(
          new Date(permission.observedAt) <= new Date(policyHead.observedAt) &&
            new Date(policyHead.observedAt) <= new Date(payload.effectiveFrom) &&
            new Date(payload.effectiveFrom) - new Date(policyHead.observedAt) <= features.dashboardAuthorization.maxAgeSeconds * 1000,
          `Dashboard policy ${item.evidenceId} uses a stale or causally invalid policy high-water observation`
        );
      } else {
        const defaultBranch = ofType("REPOSITORY_DEFAULT_BRANCH").find(
          (candidate) => candidate.evidenceId === payload.configurationSource.defaultBranchEvidenceId
        );
        const refSnapshot = ofType("REPOSITORY_REF_SNAPSHOT").find(
          (candidate) => candidate.evidenceId === payload.configurationSource.refSnapshotEvidenceId
        );
        const blobSnapshot = ofType("REPOSITORY_BLOB_SNAPSHOT").find(
          (candidate) => candidate.evidenceId === payload.configurationSource.blobSnapshotEvidenceId
        );
        assert(defaultBranch && refSnapshot && blobSnapshot, `Default-branch policy ${item.evidenceId} lacks its provider proof chain`);
        assert(
          payload.configurationSource.defaultBranchEvidenceId === defaultBranch.evidenceId &&
            payload.configurationSource.refSnapshotEvidenceId === refSnapshot.evidenceId &&
            payload.configurationSource.blobSnapshotEvidenceId === blobSnapshot.evidenceId,
          `Default-branch policy ${item.evidenceId} does not bind its exact provider proof chain`
        );
        assert(
          [defaultBranch, refSnapshot, blobSnapshot].every((snapshot) =>
            snapshot.canonicalPayload.installationId === payload.installationId &&
              snapshot.canonicalPayload.repositoryNodeId === payload.repositoryNodeId &&
              snapshot.canonicalPayload.providerObservedAt === snapshot.observedAt
          ),
          `Default-branch policy ${item.evidenceId} proof chain crosses installation or repository scope`
        );
        assert(
          defaultBranch.canonicalPayload.defaultBranchRef === refSnapshot.canonicalPayload.ref &&
            refSnapshot.canonicalPayload.tipCommitSha === blobSnapshot.canonicalPayload.commitSha &&
            blobSnapshot.canonicalPayload.configPath === ".github/mergesignal.yml" &&
            defaultBranch.canonicalPayload.observationBundleId === refSnapshot.canonicalPayload.observationBundleId &&
            refSnapshot.canonicalPayload.observationBundleId === blobSnapshot.canonicalPayload.observationBundleId &&
            defaultBranch.observedAt === refSnapshot.observedAt &&
            refSnapshot.observedAt === blobSnapshot.observedAt,
          `Default-branch policy ${item.evidenceId} proof chain does not resolve the configured blob from the actual default branch`
        );
        const blobBytes = Buffer.from(blobSnapshot.canonicalPayload.configurationBytesBase64, "base64");
        assert(
          blobBytes.toString("base64") === blobSnapshot.canonicalPayload.configurationBytesBase64,
          `Default-branch policy ${item.evidenceId} configuration bytes are not canonical base64`
        );
        const gitBlobIdentity = createHash("sha1")
          .update(Buffer.from(`blob ${blobBytes.length}\0`, "utf8"))
          .update(blobBytes)
          .digest("hex");
        assert(gitBlobIdentity === blobSnapshot.canonicalPayload.configBlobSha, `Default-branch policy ${item.evidenceId} Git blob identity mismatch`);
        const blobText = blobBytes.toString("utf8");
        assert(Buffer.from(blobText, "utf8").equals(blobBytes), `Default-branch policy ${item.evidenceId} configuration is not valid UTF-8`);
        const parsedConfiguration = parseMergeSignalYaml(blobBytes);
        assert(
          canonicalize(parsedConfiguration) === canonicalize(normalizedConfiguration),
          `Default-branch policy ${item.evidenceId} YAML does not encode its normalized rules`
        );
        assert(
          blobSnapshot.canonicalPayload.configurationDigest === configurationDigest &&
            canonicalDigest(parsedConfiguration) === configurationDigest,
          `Default-branch policy ${item.evidenceId} configuration digest differs from its blob`
        );
        const latestDefaultBranch = ofType("REPOSITORY_DEFAULT_BRANCH")
          .filter((candidate) =>
            candidate.canonicalPayload.installationId === payload.installationId &&
            candidate.canonicalPayload.repositoryNodeId === payload.repositoryNodeId
          )
          .sort((left, right) => new Date(right.observedAt) - new Date(left.observedAt) || compareUtf8(left.evidenceId, right.evidenceId))[0];
        assert(latestDefaultBranch?.evidenceId === defaultBranch.evidenceId, `Default-branch policy ${item.evidenceId} does not use the latest provider observation`);
        assert(
          new Date(defaultBranch.observedAt) <= new Date(payload.effectiveFrom) &&
            new Date(payload.effectiveFrom) - new Date(defaultBranch.observedAt) <=
              features.publicHistoryFreshness.maxAgeSeconds * 1000,
          `Default-branch policy ${item.evidenceId} provider proof is stale at activation`
        );
      }
      return;
    }
    case "sensitive_path_change_v1": {
      const paths = ofType("CHANGED_PATH");
      const ci = ofType("CI_CHECK_STATE")[0];
      const fileset = ofType("PATCH_FILESET_STATUS")[0];
      const policy = ofType("REPOSITORY_RISK_POLICY")[0];
      assert(ci && fileset && policy && samePullRequestIdentity(ci, fileset), "Sensitive-path source identity mismatch");
      assert(paths.every((path) => samePullRequestIdentity(path, ci)), "Sensitive-path inputs cross pull requests");
      assert(ci.canonicalPayload.headSha === fileset.canonicalPayload.headSha, "Sensitive-path CI and fileset heads differ");
      assert(paths.every((path) => path.canonicalPayload.headSha === fileset.canonicalPayload.headSha), "Sensitive-path inputs cross heads");
      assert(fileset.canonicalPayload.collectedFileCount === paths.length, "Sensitive-path fileset count mismatch");
      assert(policy.canonicalPayload.repositoryNodeId === fileset.canonicalPayload.repositoryNodeId, "Risk policy repository mismatch");
      const matches = paths
        .flatMap((path) =>
          policy.canonicalPayload.rules
            .filter((rule) => path.canonicalPayload.path.startsWith(rule.pathPrefix))
            .map((rule) => ({ path: path.canonicalPayload.path, ruleId: rule.ruleId }))
        )
        .sort((left, right) => compareUtf8(canonicalize(left), canonicalize(right)));
      assert(payload.pullRequestNodeId === fileset.canonicalPayload.pullRequestNodeId, "Sensitive-path PR mismatch");
      assert(payload.repositoryNodeId === fileset.canonicalPayload.repositoryNodeId, "Sensitive-path repository mismatch");
      assert(payload.pullRequestNumber === fileset.canonicalPayload.pullRequestNumber, "Sensitive-path number mismatch");
      assert(payload.headSha === fileset.canonicalPayload.headSha, "Sensitive-path head mismatch");
      assert(payload.filesetComplete === fileset.canonicalPayload.complete, "Sensitive-path completeness mismatch");
      assert(payload.policyId === policy.canonicalPayload.policyId, "Sensitive-path policy ID mismatch");
      assert(payload.policyVersion === policy.canonicalPayload.policyVersion, "Sensitive-path policy version mismatch");
      assert(payload.policyDigest === policy.canonicalPayload.policyDigest, "Sensitive-path policy digest mismatch");
      const state = !fileset.canonicalPayload.complete
        ? "unknown"
        : matches.length > 0
          ? "changed"
          : "unchanged";
      assert(payload.state === state, "Sensitive-path state mismatch");
      const expectedPaths = state === "changed" ? [...new Set(matches.map((match) => match.path))] : [];
      const expectedRules = state === "changed" ? [...new Set(matches.map((match) => match.ruleId))] : [];
      assert(jsonEquals(payload.paths, expectedPaths), "Sensitive path list mismatch");
      assert(jsonEquals(payload.matchedRuleIds, expectedRules), "Sensitive rule list mismatch");
      return;
    }
    default:
      throw new Error(`Derivation predicate has no implementation: ${predicate}`);
  }
}
export function exactDerivationCandidates(item, derivationIndex) {
  const payload = item.canonicalPayload;
  const typed = (...types) => derivationIndex.typed(item, ...types);
  let candidates;
  switch (item.type) {
    case "ACTIVE_MONTH":
      candidates = typed("CONTRIBUTION_YEAR").filter((candidate) =>
        candidate.canonicalPayload.activeMonths.includes(payload.yearMonth)
      );
      break;
    case "REPOSITORY_OWNERSHIP_RELATIONSHIP":
      candidates = derivationIndex.prTyped(
        item,
        payload.pullRequestNodeId,
        "PULL_REQUEST_OPENED",
        "PULL_REQUEST_MERGED",
        "MERGE_ACTOR"
      );
      break;
    case "DEPENDENCY_ECOSYSTEM":
      candidates = derivationIndex.repoPathTyped(item, payload.repositoryNodeId, payload.manifestPath, "CHANGED_PATH");
      break;
    case "ACTIVITY_BURST":
    case "BEHAVIOR_BASELINE_CHANGE": {
      const window = new Set(Array.from({ length: 15 }, (_, index) => monthOffset(payload.windowEndMonth, -index)));
      candidates = [...window].flatMap((month) => derivationIndex.monthTyped(item, month, "ACTIVE_MONTH"));
      break;
    }
    case "TEMPLATE_SIMILARITY":
      candidates = typed("PULL_REQUEST_OPENED", "REPOSITORY_OWNERSHIP_RELATIONSHIP");
      break;
    case "RECIPROCAL_MERGE_EDGE":
      candidates = [
        ...derivationIndex.actorPairTyped(item, payload.subjectNodeId, payload.counterpartyNodeId, "MERGE_RELATIONSHIP_EVENT"),
        ...derivationIndex.actorPairTyped(item, payload.counterpartyNodeId, payload.subjectNodeId, "MERGE_RELATIONSHIP_EVENT")
      ];
      break;
    case "RELEVANCE_COMPARISON": {
      candidates = [
        ...derivationIndex.prTyped(item, payload.historicalPullRequestNodeId, "PULL_REQUEST_OPENED"),
        ...derivationIndex.prHeadTyped(item, payload.historicalPullRequestNodeId, payload.historicalHeadSha, "CHANGED_PATH"),
        ...derivationIndex.prHeadTyped(item, payload.targetPullRequestNodeId, payload.targetHeadSha, "CHANGED_PATH"),
        ...derivationIndex.byEvidenceIds(item, [payload.historicalFilesetEvidenceId, payload.targetFilesetEvidenceId]),
        ...derivationIndex.repoTyped(item, payload.historicalRepositoryNodeId, "REPOSITORY_LANGUAGE", "REPOSITORY_TOPIC", "DEPENDENCY_ECOSYSTEM"),
        ...derivationIndex.repoTyped(item, payload.targetRepositoryNodeId, "REPOSITORY_LANGUAGE", "REPOSITORY_TOPIC", "DEPENDENCY_ECOSYSTEM")
      ];
      break;
    }
    case "REPOSITORY_RISK_POLICY": {
      const sourceTypes = payload.configurationSource.kind === "dashboard_revision"
        ? [
            "REPOSITORY_ADMIN_PERMISSION",
            "DASHBOARD_POLICY_REVISION",
            "DASHBOARD_POLICY_STREAM_HEAD"
          ]
        : [
            "REPOSITORY_DEFAULT_BRANCH",
            "REPOSITORY_REF_SNAPSHOT",
            "REPOSITORY_BLOB_SNAPSHOT"
          ];
      candidates = derivationIndex.repoTyped(item, payload.repositoryNodeId, ...sourceTypes);
      break;
    }
    case "PATCH_SCOPE":
    case "TEST_PATH_CHANGE":
      candidates = derivationIndex.prHeadTyped(
        item,
        payload.pullRequestNodeId,
        payload.headSha,
        "CHANGED_PATH",
        "CI_CHECK_STATE",
        "PATCH_FILESET_STATUS"
      );
      break;
    case "SENSITIVE_PATH_CHANGE":
      candidates = [
        ...derivationIndex.prHeadTyped(
          item,
          payload.pullRequestNodeId,
          payload.headSha,
          "CHANGED_PATH",
          "CI_CHECK_STATE",
          "PATCH_FILESET_STATUS"
        ),
        ...derivationIndex.repoTyped(item, payload.repositoryNodeId, "REPOSITORY_RISK_POLICY")
          .filter((candidate) => candidate.canonicalPayload.policyId === payload.policyId)
      ];
      break;
    default:
      throw new Error(`Exact candidate policy is missing for ${item.type}`);
  }
  return new Set(candidates.map((candidate) => candidate.evidenceId));
}

function roundTo(value, precision) {
  const multiplier = 10 ** precision;
  return Math.round((value + Number.EPSILON) * multiplier) / multiplier;
}

export function calculateDimension(dimensionName, dimension, coverageConfidence, scoring, manualInspectionReasons) {
  const rule = scoring.dimensions[dimensionName];
  const weightedReasons = dimension.reasonCodes.filter((code) => rule.reasonWeights[code] !== undefined);
  const manual = dimension.reasonCodes.some((code) => manualInspectionReasons.includes(code));
  const weightedScore = weightedReasons.reduce((total, code) => total + rule.reasonWeights[code], 0);
  const confidence = dimension.evidenceIds.length === 0
    ? rule.emptyEvidenceConfidence
    : roundTo(Math.min(
        coverageConfidence,
        rule.maximumConfidence,
        rule.baseConfidence + weightedReasons.length * rule.confidencePerSupportingReason
      ), 2);
  if (manual) return { score: null, state: "manual_inspection", confidence };
  if (weightedScore >= scoring.stateThresholds.strong) return { score: weightedScore, state: "strong", confidence };
  if (weightedScore >= scoring.stateThresholds.moderate) return { score: weightedScore, state: "moderate", confidence };
  if (weightedReasons.length > 0) return { score: null, state: "limited", confidence };
  return { score: null, state: rule.emptyState, confidence };
}

export function classifyAssessment({ assessment, assessmentReasonCodes, scoringPolicy, productPolicy, manualInspectionReasons, patchInspectionReasons }) {
  const assessmentReasons = new Set(assessmentReasonCodes);
  const expectedDimensions = Object.fromEntries(
    Object.entries(assessment.dimensions).map(([dimensionName, dimension]) => [
      dimensionName,
      calculateDimension(dimensionName, dimension, assessment.coverage.confidence, scoringPolicy, manualInspectionReasons)
    ])
  );
  const coreConfidences = scoringPolicy.overallConfidence.coreDimensions.map(
    (dimension) => assessment.dimensions[dimension].confidence
  );
  const expectedOverallConfidence = roundTo(
    Math.min(
      assessment.coverage.confidence,
      coreConfidences.reduce((total, value) => total + value, 0) / coreConfidences.length
    ),
    scoringPolicy.overallConfidence.precision
  );
  const activeManualReasons = manualInspectionReasons.filter((reason) => assessmentReasons.has(reason));
  const manualDimensionPresent = Object.values(assessment.dimensions).some((dimension) => dimension.state === "manual_inspection");
  const manualTriggerPresent = activeManualReasons.length > 0 || manualDimensionPresent;
  const establishedCoreDimensions = [
    assessment.dimensions.tenure_continuity,
    assessment.dimensions.independent_open_source_record,
    assessment.dimensions.merge_follow_through
  ];
  const qualifiesForEstablishedEvidence =
    assessment.assessmentStatus === "complete" &&
    assessment.subject.actorType === "User" &&
    assessment.subject.historySupport === "full" &&
    assessment.coverage.completeYears >= 3 &&
    assessment.coverage.confidence >= 0.75 &&
    assessment.overallConfidence.label === "high" &&
    !manualTriggerPresent &&
    assessmentReasons.has("INDEPENDENT_MERGES") &&
    assessmentReasons.has("MULTI_REPOSITORY_VALIDATION") &&
    establishedCoreDimensions.every((dimension) => ["strong", "moderate"].includes(dimension.state));
  const supportedDimensionPresent = Object.values(assessment.dimensions).some(
    (dimension) => ["strong", "moderate"].includes(dimension.state) && dimension.evidenceIds.length > 0
  );
  const limitingReasonPresent = [
    "LIMITED_PUBLIC_HISTORY",
    "HISTORY_PARTIALLY_ACCESSIBLE",
    "HISTORY_TRUNCATED",
    "EVIDENCE_STALE",
    "ATTRIBUTION_UNCERTAIN",
    "UNSUPPORTED_ACTOR_TYPE",
    "AUTHOR_UNAVAILABLE"
  ].some((reason) => assessmentReasons.has(reason));
  const summaryState = manualTriggerPresent
    ? "needs_manual_inspection"
    : qualifiesForEstablishedEvidence
      ? "established_evidence"
      : limitingReasonPresent || assessment.assessmentStatus === "partial" ||
          assessment.coverage.completeYears < 2 || assessment.overallConfidence.label === "low" ||
          !supportedDimensionPresent
        ? "limited_evidence"
        : "developing_evidence";
  const inspectionTriggerPresent = [...manualInspectionReasons, ...patchInspectionReasons]
    .some((reason) => assessmentReasons.has(reason));
  const reputationPatchRequirements = productPolicy.reviewPriority.reputationAndPatchRequiredFacts;
  const reputationPatchQualified =
    assessment.patchContext.ciState === reputationPatchRequirements.ciState &&
    reputationPatchRequirements.allowedScopes.includes(assessment.patchContext.scope) &&
    reputationPatchRequirements.allowedTestPathStates.includes(assessment.patchContext.testPathState) &&
    assessment.patchContext.sensitivePathState === reputationPatchRequirements.sensitivePathState &&
    !productPolicy.reviewPriority.forbiddenPatchFacts.some((reason) => assessmentReasons.has(reason));
  const patchOnlyRequirements = productPolicy.reviewPriority.patchOnlyRequiredFacts;
  const patchOnlyFactsQualified =
    assessment.patchContext.ciState === patchOnlyRequirements.ciState &&
    assessment.patchContext.scope === patchOnlyRequirements.scope &&
    assessment.patchContext.testPathState === patchOnlyRequirements.testPathState &&
    assessment.patchContext.sensitivePathState === patchOnlyRequirements.sensitivePathState &&
    !productPolicy.reviewPriority.forbiddenPatchFacts.some((reason) => assessmentReasons.has(reason));
  const reputationQualifiedForPriority =
    qualifiesForEstablishedEvidence && assessment.overallConfidence.label === "high" &&
    assessment.coverage.confidence >= 0.75 &&
    productPolicy.reviewPriority.reputationRequiredRelevantExperienceStates.includes(
      assessment.dimensions.relevant_experience.state
    ) && reputationPatchQualified;
  const patchOnlyQualifiedForPriority =
    productPolicy.reviewPriority.patchQualifiedLimitedHistoryAllowed &&
    ["limited_evidence", "developing_evidence"].includes(assessment.summaryState) &&
    productPolicy.reviewPriority.patchQualifiedActorTypes.includes(assessment.subject.actorType) &&
    patchOnlyFactsQualified;
  const reviewPriority = !assessment.target.riskPolicy.reviewPriorityEnabled
    ? "not_enabled"
    : inspectionTriggerPresent
      ? "inspect_first"
      : reputationQualifiedForPriority || patchOnlyQualifiedForPriority
        ? "prioritize"
        : "standard";
  const reviewPriorityBasis = reviewPriority === "not_enabled"
    ? "disabled"
    : reviewPriority === "inspect_first"
      ? "inspection"
      : reviewPriority === "standard"
        ? "standard"
        : reputationQualifiedForPriority
          ? "reputation_and_patch"
          : "patch_only";
  return {
    expectedDimensions,
    expectedOverallConfidence,
    activeManualReasons,
    manualDimensionPresent,
    manualTriggerPresent,
    establishedCoreDimensions,
    qualifiesForEstablishedEvidence,
    supportedDimensionPresent,
    limitingReasonPresent,
    summaryState,
    inspectionTriggerPresent,
    reputationQualifiedForPriority,
    patchOnlyQualifiedForPriority,
    reviewPriority,
    reviewPriorityBasis
  };
}

function boundedEvidenceExemplars(sortedPopulation, maximum = 64) {
  if (sortedPopulation.length <= maximum) return sortedPopulation;
  return Array.from({ length: maximum }, (_, index) =>
    sortedPopulation[Math.floor((index * (sortedPopulation.length - 1)) / (maximum - 1))]
  );
}

export function expandEligibleDerivations(seedIds, items, isEligibleCandidate) {
  const eligible = new Set(seedIds);
  const remainingInputs = new Map();
  const dependentsByInput = new Map();
  for (const item of items) {
    const inputs = item.derivation?.inputEvidenceIds ?? [];
    if (!isEligibleCandidate(item) || inputs.length === 0 || eligible.has(item.evidenceId)) continue;
    remainingInputs.set(item.evidenceId, inputs.filter((id) => !eligible.has(id)).length);
    for (const inputId of inputs) {
      const dependents = dependentsByInput.get(inputId) ?? [];
      dependents.push(item.evidenceId);
      dependentsByInput.set(inputId, dependents);
    }
  }
  const queue = [...eligible];
  for (const [id, remaining] of remainingInputs) {
    if (remaining === 0) {
      eligible.add(id);
      queue.push(id);
    }
  }
  for (let index = 0; index < queue.length; index += 1) {
    for (const dependentId of dependentsByInput.get(queue[index]) ?? []) {
      if (eligible.has(dependentId)) continue;
      const remaining = remainingInputs.get(dependentId) - 1;
      remainingInputs.set(dependentId, remaining);
      if (remaining === 0) {
        eligible.add(dependentId);
        queue.push(dependentId);
      }
    }
  }
  return eligible;
}

export function buildAuthoritativeHistoryEvidenceIds({
  coverageItem,
  manifestItems,
  assessment,
  evidenceById,
  features,
  assert
}) {
  const coveredCandidateEvidenceIds = new Set(
    coverageItem.canonicalPayload.sourcePartitions.flatMap(
      (partition) => partition.candidateEvidenceIds
    )
  );
  const publicHistory = expandEligibleDerivations(
    new Set([...coveredCandidateEvidenceIds, coverageItem.evidenceId]),
    manifestItems,
    (item) =>
      item.subjectGithubNodeId === coverageItem.subjectGithubNodeId &&
      item.collectionRunId === coverageItem.collectionRunId &&
      ["PUBLIC_DERIVED", "PUBLIC_GLOBAL"].includes(item.visibility)
  );
  if (!assessment) return publicHistory;

  const eligible = new Set(publicHistory);
  const privateTargetFactTypes = new Set([
    "REPOSITORY_LANGUAGE",
    "REPOSITORY_TOPIC",
    "CHANGED_PATH",
    "PATCH_FILESET_STATUS"
  ]);
  for (const item of evidenceById.values()) {
    if (
      item.visibility !== "TARGET_REPOSITORY_PRIVATE" ||
      item.collectionRunId !== coverageItem.collectionRunId ||
      (item.repositoryNodeId ?? item.canonicalPayload.repositoryNodeId) !== assessment.target.repositoryNodeId ||
      !privateTargetFactTypes.has(item.type)
    ) continue;
    const identity = pullRequestIdentity(item);
    assert(
      identity === null || identity.pullRequestNodeId === assessment.target.pullRequestNodeId,
      `Private target fact ${item.evidenceId} identifies another pull request`
    );
    if (item.canonicalPayload.headSha !== undefined) {
      assert(
        item.canonicalPayload.headSha === assessment.target.headSha,
        `Private target fact ${item.evidenceId} identifies another head`
      );
    }
    assert(
      new Date(assessment.evidenceSnapshot.capturedAt) - new Date(item.observedAt) <=
        features.publicHistoryFreshness.maxAgeSeconds * 1000,
      `Private target fact ${item.evidenceId} is stale for this assessment`
    );
    eligible.add(item.evidenceId);
  }
  return expandEligibleDerivations(
    eligible,
    evidenceById.values(),
    (item) =>
      item.subjectGithubNodeId === assessment.subject.githubNodeId &&
      item.collectionRunId === coverageItem.collectionRunId
  );
}

function evidenceRuleSatisfied(rule, evidenceIds, evidenceById) {
  const types = new Set(evidenceIds.map((id) => evidenceById.get(id)?.type));
  return rule.requiredAll.every((type) => types.has(type)) &&
    (rule.requiredAny.length === 0 || rule.requiredAny.some((type) => types.has(type)));
}

export function authoritativeReasonEvidenceIds(reason, assessment, evidenceById, authoritativeHistoryEvidenceIds) {
  const allowedTypes = new Set([...reason.evidenceRule.requiredAll, ...reason.evidenceRule.requiredAny]);
  const eligibleIds = [...authoritativeHistoryEvidenceIds].filter((id) => allowedTypes.has(evidenceById.get(id)?.type));
  if (reason.dimension !== "relevant_experience") return eligibleIds.sort(compareUtf8);
  const selected = new Set();
  for (const id of eligibleIds) {
    const item = evidenceById.get(id);
    if (item.type !== "RELEVANCE_COMPARISON" ||
        item.canonicalPayload.targetPullRequestNodeId !== assessment.target.pullRequestNodeId ||
        item.canonicalPayload.targetRepositoryNodeId !== assessment.target.repositoryNodeId ||
        item.canonicalPayload.targetHeadSha !== assessment.target.headSha) continue;
    selected.add(id);
    for (const inputId of item.derivation?.inputEvidenceIds ?? []) {
      if (authoritativeHistoryEvidenceIds.has(inputId) && allowedTypes.has(evidenceById.get(inputId)?.type)) selected.add(inputId);
    }
  }
  return [...selected].sort(compareUtf8);
}

function boundedPredicateWitness(populationEvidenceIds, reason, evidenceById, evaluate, metrics, assert, maximum = 64) {
  const byType = new Map();
  for (const evidenceId of populationEvidenceIds) {
    const type = evidenceById.get(evidenceId)?.type;
    const values = byType.get(type) ?? [];
    values.push(evidenceId);
    byType.set(type, values);
    metrics.populationEvidenceVisits += 1;
  }
  const relevantTypes = [...new Set([...reason.evidenceRule.requiredAll, ...reason.evidenceRule.requiredAny])]
    .sort(compareUtf8);
  const perType = Math.max(1, Math.floor(maximum / Math.max(1, relevantTypes.length)));
  let candidate = [...new Set(relevantTypes.flatMap((type) =>
    boundedEvidenceExemplars(byType.get(type) ?? [], perType)
  ))].sort(compareUtf8).slice(0, maximum);
  const passes = (ids) => {
    metrics.predicateEvaluations += 1;
    return evidenceRuleSatisfied(reason.evidenceRule, ids, evidenceById) && evaluate(reason, ids);
  };
  if (!passes(candidate)) {
    metrics.fullPopulationFallbacks += 1;
    if (!passes(populationEvidenceIds)) {
      assert(false, `Candidate ${reason.code} does not satisfy its versioned predicate`);
    }
    return {
      witnessMode: "full_population_commitment",
      witnessEvidenceIds: boundedEvidenceExemplars(populationEvidenceIds, maximum)
    };
  }
  for (const evidenceId of [...candidate].reverse()) {
    const reduced = candidate.filter((id) => id !== evidenceId);
    if (reduced.length > 0 && passes(reduced)) candidate = reduced;
  }
  return { witnessMode: "bounded_witness", witnessEvidenceIds: candidate };
}

export function buildContextualizationCandidates({ assessment, evidenceById, reasonByCode, authoritativeHistoryEvidenceIds, features, assert, metrics = {} }) {
  metrics.populationEvidenceVisits = 0;
  metrics.predicateEvaluations = 0;
  metrics.fullPopulationFallbacks = 0;
  return contextualizationDimensionOrder.flatMap((dimension) => [...assessment.dimensions[dimension].reasonCodes].sort(compareUtf8).map((reasonCode) => {
    const reason = reasonByCode.get(reasonCode);
    assert(reason?.dimension === dimension, `Candidate reason ${reasonCode} is outside ${dimension}`);
    const populationEvidenceIds = authoritativeReasonEvidenceIds(reason, assessment, evidenceById, authoritativeHistoryEvidenceIds);
    assert(populationEvidenceIds.length > 0, `Candidate ${reasonCode} has no authoritative evidence`);
    const { witnessMode, witnessEvidenceIds } = boundedPredicateWitness(
      populationEvidenceIds,
      reason,
      evidenceById,
      (selectedReason, evidenceIds) => evaluateVersionedReasonPredicate({
        predicate: selectedReason.evidenceRule.predicate,
        evidenceIds,
        evidenceById,
        subjectNodeId: assessment.subject.githubNodeId,
        target: assessment.target,
        features,
        authoritativeHistoryEvidenceIds
      }),
      metrics,
      assert
    );
    return {
      claimId: `claim-${reasonCode.toLowerCase().replaceAll("_", "-")}`,
      reasonCode,
      populationEvidenceCount: populationEvidenceIds.length,
      populationDigest: createHash("sha256").update(canonicalize(populationEvidenceIds), "utf8").digest("hex"),
      witnessMode,
      witnessEvidenceIds,
      evidenceIds: boundedEvidenceExemplars(populationEvidenceIds)
    };
  }));
}
export function classifyPublication({ fenceState, commentState, checkState, checkConclusion }) {
  return fenceState === "stale"
    ? "stale"
    : fenceState === "repair_queued"
      ? "repair_queued"
      : checkConclusion === "action_required"
        ? "action_required"
        : commentState === "published" && checkConclusion === "success"
          ? "published"
          : commentState === "failed" || checkConclusion === "failure"
            ? "failed"
            : commentState === "retrying" || checkState === "retrying"
              ? "retrying"
              : commentState === "publishing" || checkState === "in_progress"
                ? "publishing"
                : "queued";
}

export function evaluatePublicationFence({ checkConclusion, postWritePublishable, postCheckPublishable }) {
  const successfulCheck = checkConclusion === "success";
  return {
    successfulCheck,
    publishableSuccess: successfulCheck && postWritePublishable && postCheckPublishable,
    requiresRepair: successfulCheck && (!postWritePublishable || !postCheckPublishable)
  };
}

export function requiresCommentRemoval({ retentionState, commentId, commentWriteCompletedAt }) {
  return ["subject_deleted", "expired"].includes(retentionState) &&
    commentId !== null && commentWriteCompletedAt !== null;
}
