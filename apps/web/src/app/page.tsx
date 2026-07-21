export default function FoundationPage() {
  return (
    <main>
      <p className="eyebrow">MergeSignal</p>
      <h1>Trust context for every pull request.</h1>
      <p className="summary">
        The production foundation is online. Contributor evidence, confidence, and repository context
        will remain separate from patch safety and code review.
      </p>
      <dl>
        <div>
          <dt>Control plane</dt>
          <dd>Next.js on Vercel</dd>
        </div>
        <div>
          <dt>Durability</dt>
          <dd>Temporal Cloud and PostgreSQL</dd>
        </div>
        <div>
          <dt>Worker</dt>
          <dd>Versioned container on Coolify</dd>
        </div>
      </dl>
    </main>
  );
}
