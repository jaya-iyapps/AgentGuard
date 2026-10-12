import { useEffect, useState } from "react";

import { checkBackend, type BackendStatus } from "./health";

const modules = [
  ["01", "Policy & capability graph", "Deterministic policy and graph interfaces", "Teammate 1"],
  ["02", "Salesforce & Agentforce", "DX project and adapter boundaries", "Teammate 2"],
  ["03", "MCP gateway", "Configuration and authentication interfaces", "Teammate 3"],
  ["04", "Frontend & integration", "React shell and shared contract fixtures", "Teammate 4"],
];

export function App() {
  const [status, setStatus] = useState<BackendStatus>("checking");

  useEffect(() => {
    const controller = new AbortController();
    void checkBackend(controller.signal).then((next) => {
      if (!controller.signal.aborted) setStatus(next);
    });
    return () => controller.abort();
  }, []);

  return (
    <main>
      <header>
        <a className="brand" href="/" aria-label="AgentGuard home">
          AG<span>AgentGuard</span>
        </a>
        <span className="tag">Development scaffold</span>
      </header>
      <section className="intro" aria-labelledby="page-title">
        <p className="eyebrow">CAPABILITYGRAPH / TEAM WORKSPACE</p>
        <h1 id="page-title">
          A shared foundation.
          <br />
          Four focused workstreams.
        </h1>
        <p>
          Start building continuous authorization for autonomous agents. The project structure,
          contracts, and integration boundaries are ready for your team.
        </p>
        <div className={`status ${status}`} role="status" aria-live="polite">
          <span className="dot" />
          Backend: {status === "online" ? "connected" : status}
          <span className="status-detail">GET /health</span>
        </div>
      </section>
      <section className="modules" aria-label="Team workstreams">
        {modules.map(([number, title, description, owner]) => (
          <article key={number}>
            <span className="number">{number}</span>
            <h2>{title}</h2>
            <p>{description}</p>
            <span className="owner">{owner}</span>
          </article>
        ))}
      </section>
      <aside>
        <strong>Scaffold only.</strong> No real authorization, tool execution, Salesforce connection,
        or graph analysis is implemented. Authorization placeholders always return DENY.
      </aside>
      <footer>
        Start with README.md · Interfaces in packages/contracts · Tasks in docs/team-roles.md
      </footer>
    </main>
  );
}
