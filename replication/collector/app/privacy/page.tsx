export default function PrivacyPage() {
  return (
    <main>
      <div className="card legal-page">
        <h1>Privacy Policy</h1>
        <p>
          OpenHookbin stores the requests that users send to generated bin URLs so they can be inspected in the
          console and through the API.
        </p>
        <p>The stored data may include request method, path, query parameters, selected headers, content type, and body.</p>
        <p>
          Some headers are redacted before storage, including <code>x-vercel-*</code>, <code>forwarded</code>,{" "}
          <code>x-forwarded-*</code>, and <code>x-real-ip</code>.
        </p>
        <p>
          Request logs are retained for up to 24 hours. After that they are excluded from the application and deleted
          during cleanup.
        </p>
        <p>
          The service is hosted on Vercel and uses Neon as database provider. Their infrastructure may process technical
          connection data required to operate the service.
        </p>
        <p>
          Contact: <a href="mailto:open-hookbin@example.invalid">open-hookbin@example.invalid</a>
        </p>
        <p>
          This page describes the current technical behavior of the app and is not a substitute for jurisdiction-specific
          legal review.
        </p>
      </div>
    </main>
  );
}
