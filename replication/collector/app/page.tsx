export default function HomePage() {
  return (
    <main>
      <div className="card grid">
        <h1>OpenHookbin</h1>
        <p>Send webhook requests to any path and inspect them in a live console.</p>
        <p>
          Example:
          <br />
          <code>POST /demo-bin</code>
          <br />
          Console: <code>/console/demo-bin</code>
          <br />
          API: <code>/api/demo-bin</code>
        </p>
        <details className="info-box">
          <summary>Header redaction</summary>
          <small>
            OpenHookbin does not store or display some infrastructure headers, including <code>x-vercel-*</code>,{" "}
            <code>forwarded</code>, <code>x-forwarded-*</code>, and <code>x-real-ip</code>.
          </small>
        </details>
        <p>
          Source code:{" "}
          <a href="./replication/collector" target="_blank" rel="noreferrer">
            github.com/anonymous-author/open-hookbin
          </a>
        </p>
      </div>
    </main>
  );
}
