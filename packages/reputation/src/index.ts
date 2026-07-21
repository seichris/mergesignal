import { z } from "zod";

export const MVP_SCORING_VERSION = "mvp-v1" as const;

const count = z.number().int().min(0).max(1_000_000_000);

export const publicContributorHistorySchema = z
  .object({
    actorNodeId: z.string().min(1).max(255),
    login: z.string().regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/),
    accountCreatedAt: z.iso.datetime(),
    observedFrom: z.iso.datetime(),
    observedUntil: z.iso.datetime(),
    accountAgeDays: count,
    commits: count,
    issues: count,
    pullRequests: count,
    pullRequestReviews: count,
    activeWeeks: z.number().int().min(0).max(104),
    externalPullRequestsObserved: count,
    externalClosedPullRequests: count,
    externalMergedPullRequests: count,
    distinctPublicRepositories: count,
    restrictedContributions: count,
    truncated: z.boolean()
  })
  .superRefine((history, context) => {
    if (new Date(history.observedFrom) >= new Date(history.observedUntil)) {
      context.addIssue({ code: "custom", path: ["observedFrom"], message: "must precede observedUntil" });
    }
    if (history.externalClosedPullRequests > history.externalPullRequestsObserved) {
      context.addIssue({
        code: "custom",
        path: ["externalClosedPullRequests"],
        message: "cannot exceed observed external pull requests"
      });
    }
    if (history.externalMergedPullRequests > history.externalClosedPullRequests) {
      context.addIssue({
        code: "custom",
        path: ["externalMergedPullRequests"],
        message: "cannot exceed closed external pull requests"
      });
    }
  });

export type PublicContributorHistory = z.infer<typeof publicContributorHistorySchema>;

export const reputationBandSchema = z.enum([
  "extensive",
  "substantial",
  "moderate",
  "emerging",
  "limited"
]);
export type ReputationBand = z.infer<typeof reputationBandSchema>;

export const evidenceConfidenceSchema = z.enum(["high", "medium", "limited"]);
export type EvidenceConfidence = z.infer<typeof evidenceConfidenceSchema>;

export interface ReputationComponents {
  accountMaturity: number;
  publicActivity: number;
  regularity: number;
  mergedPullRequests: number;
  repositoryBreadth: number;
}

export interface ReputationScore {
  scoringVersion: typeof MVP_SCORING_VERSION;
  score: number;
  band: ReputationBand;
  confidence: EvidenceConfidence;
  components: ReputationComponents;
}

export type ReputationAssessmentReport =
  | {
      status: "evaluated";
      actorNodeId: string;
      login: string;
      history: PublicContributorHistory;
      result: ReputationScore;
    }
  | {
      status: "not_evaluated";
      actorNodeId: string | null;
      login: string | null;
      reason: "author_missing" | "actor_not_user";
    }
  | {
      status: "unavailable";
      actorNodeId: string | null;
      login: string | null;
      reason: "provider_unavailable" | "identity_mismatch" | "invalid_provider_data";
    };

function boundedRatio(value: number, maximum: number): number {
  return Math.min(Math.max(value / maximum, 0), 1);
}

function component(value: number, maximum: number): number {
  return Math.min(Math.max(value, 0), maximum);
}

export function bandForScore(score: number): ReputationBand {
  if (!Number.isInteger(score) || score < 0 || score > 100) {
    throw new Error("Reputation score must be an integer from 0 through 100");
  }
  if (score >= 80) return "extensive";
  if (score >= 60) return "substantial";
  if (score >= 40) return "moderate";
  if (score >= 20) return "emerging";
  return "limited";
}

export function confidenceForHistory(historyInput: PublicContributorHistory): EvidenceConfidence {
  const history = publicContributorHistorySchema.parse(historyInput);
  if (history.truncated) return "limited";
  if (history.activeWeeks >= 26 && history.externalClosedPullRequests >= 10) return "high";
  if (history.activeWeeks >= 8 && history.externalClosedPullRequests >= 3) return "medium";
  return "limited";
}

export function calculateReputation(historyInput: PublicContributorHistory): ReputationScore {
  const history = publicContributorHistorySchema.parse(historyInput);
  const accountMaturity = component(15 * boundedRatio(history.accountAgeDays, 1_095), 15);
  const weightedActivity =
    history.commits +
    history.issues +
    3 * history.pullRequests +
    2 * history.pullRequestReviews;
  const publicActivity = component(
    20 * Math.min(Math.log1p(weightedActivity) / Math.log1p(500), 1),
    20
  );
  const regularity = component(20 * boundedRatio(history.activeWeeks, 52), 20);
  const mergeVolume = component(
    25 * Math.min(Math.log1p(history.externalMergedPullRequests) / Math.log1p(25), 1),
    25
  );
  const sampleWeight = boundedRatio(history.externalClosedPullRequests, 5);
  const mergeRatio =
    history.externalMergedPullRequests / Math.max(history.externalClosedPullRequests, 1);
  const mergeQuality = component(10 * mergeRatio * sampleWeight, 10);
  const mergedPullRequests = component(mergeVolume + mergeQuality, 35);
  const repositoryBreadth = component(
    10 * boundedRatio(history.distinctPublicRepositories, 5),
    10
  );
  const components = {
    accountMaturity,
    publicActivity,
    regularity,
    mergedPullRequests,
    repositoryBreadth
  };
  const score = Math.min(100, Math.max(0, Math.round(Object.values(components).reduce(
    (total, value) => total + value,
    0
  ))));
  return {
    scoringVersion: MVP_SCORING_VERSION,
    score,
    band: bandForScore(score),
    confidence: confidenceForHistory(history),
    components
  };
}

export function totalPublicContributions(history: PublicContributorHistory): number {
  return history.commits + history.issues + history.pullRequests + history.pullRequestReviews;
}
