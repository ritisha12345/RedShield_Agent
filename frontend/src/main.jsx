import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";

import { createScan, getScan, scanStreamUrl } from "./api";
import "./styles.css";

const EVENT_TYPES = [
  "attack_generated",
  "violation_found",
  "patch_applied",
  "round_completed",
  "scan_completed",
  "scan_failed"
];

const DEFAULT_FORM = {
  app_category: "customer_support",
  system_prompt: "",
  attacks_per_category: 1,
  success_threshold: 0.05,
  max_rounds: 1,
  mock_target_response: "Mock target response: request handled safely."
};

function App() {
  const [route, setRoute] = useState(readRoute);
  const [lastScanId, setLastScanId] = useState(
    () => window.localStorage.getItem("redshield:lastScanId") || ""
  );

  useEffect(() => {
    const onHashChange = () => setRoute(readRoute());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const onScanCreated = (scanId) => {
    window.localStorage.setItem("redshield:lastScanId", scanId);
    setLastScanId(scanId);
    navigate(`/live/${scanId}`);
  };

  return (
    <main className="app-shell">
      <header className="topbar">
        <button className="brand-button" onClick={() => navigate("/")}>
          <span className="brand-mark">R</span>
          <span>RedShield</span>
        </button>
        <nav className="nav-actions" aria-label="Primary">
          <button onClick={() => navigate("/")}>Setup</button>
          <button
            disabled={!lastScanId}
            onClick={() => navigate(`/live/${lastScanId}`)}
          >
            Live Scan
          </button>
          <button
            disabled={!lastScanId}
            onClick={() => navigate(`/report/${lastScanId}`)}
          >
            Report
          </button>
        </nav>
      </header>

      {route.page === "live" && route.scanId ? (
        <LiveScanPage scanId={route.scanId} />
      ) : route.page === "report" && route.scanId ? (
        <ReportPage scanId={route.scanId} />
      ) : (
        <SetupPage onScanCreated={onScanCreated} />
      )}
    </main>
  );
}

function SetupPage({ onScanCreated }) {
  const [form, setForm] = useState(DEFAULT_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const updateField = (field, value) => {
    setForm((current) => ({ ...current, [field]: value }));
  };

  const submitScan = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError("");

    try {
      const response = await createScan({
        ...form,
        attacks_per_category: Number(form.attacks_per_category),
        success_threshold: Number(form.success_threshold),
        max_rounds: Number(form.max_rounds)
      });
      onScanCreated(response.scan_id);
    } catch (scanError) {
      setError(scanError.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="page-grid">
      <div className="page-heading">
        <p className="eyebrow">Phase 4</p>
        <h1>Start a safety scan</h1>
      </div>

      <form className="panel setup-form" onSubmit={submitScan}>
        <label>
          <span>App category</span>
          <input
            value={form.app_category}
            onChange={(event) => updateField("app_category", event.target.value)}
            required
          />
        </label>

        <label>
          <span>System prompt</span>
          <textarea
            value={form.system_prompt}
            onChange={(event) => updateField("system_prompt", event.target.value)}
            rows={10}
            required
          />
        </label>

        <div className="form-row">
          <label>
            <span>Attacks per category</span>
            <input
              type="number"
              min="1"
              value={form.attacks_per_category}
              onChange={(event) =>
                updateField("attacks_per_category", event.target.value)
              }
            />
          </label>
          <label>
            <span>Max rounds</span>
            <input
              type="number"
              min="0"
              value={form.max_rounds}
              onChange={(event) => updateField("max_rounds", event.target.value)}
            />
          </label>
          <label>
            <span>Success threshold</span>
            <input
              type="number"
              min="0"
              max="1"
              step="0.01"
              value={form.success_threshold}
              onChange={(event) =>
                updateField("success_threshold", event.target.value)
              }
            />
          </label>
        </div>

        <label>
          <span>Mock target response</span>
          <textarea
            value={form.mock_target_response}
            onChange={(event) =>
              updateField("mock_target_response", event.target.value)
            }
            rows={4}
            required
          />
        </label>

        {error ? <p className="error-text">{error}</p> : null}

        <button className="primary-button" type="submit" disabled={submitting}>
          {submitting ? "Starting scan..." : "Start scan"}
        </button>
      </form>
    </section>
  );
}

function LiveScanPage({ scanId }) {
  const [events, setEvents] = useState([]);
  const [scan, setScan] = useState(null);
  const [connectionState, setConnectionState] = useState("connecting");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;

    getScan(scanId)
      .then((nextScan) => {
        if (active) {
          setScan(nextScan);
        }
      })
      .catch((scanError) => {
        if (active) {
          setError(scanError.message);
        }
      });

    return () => {
      active = false;
    };
  }, [scanId]);

  useEffect(() => {
    const source = new EventSource(scanStreamUrl(scanId));
    setConnectionState("connecting");

    const receiveEvent = (message) => {
      const parsed = parseSsePayload(message.data);
      if (!parsed) {
        return;
      }

      setEvents((current) => {
        if (current.some((event) => event.event_id === parsed.event_id)) {
          return current;
        }
        return [...current, parsed];
      });

      if (parsed.type === "scan_completed" || parsed.type === "scan_failed") {
        source.close();
        setConnectionState("closed");
        getScan(scanId)
          .then(setScan)
          .catch((scanError) => setError(scanError.message));
      }
    };

    EVENT_TYPES.forEach((eventType) => {
      source.addEventListener(eventType, receiveEvent);
    });

    source.onopen = () => setConnectionState("open");
    source.onerror = () => {
      setConnectionState((current) =>
        current === "closed" ? "closed" : "reconnecting"
      );
    };

    return () => {
      EVENT_TYPES.forEach((eventType) => {
        source.removeEventListener(eventType, receiveEvent);
      });
      source.close();
    };
  }, [scanId]);

  const metrics = useMemo(() => buildLiveMetrics(events, scan), [events, scan]);

  return (
    <section className="page-stack">
      <div className="page-title-row">
        <div>
          <p className="eyebrow">Live scan</p>
          <h1>{scanId}</h1>
        </div>
        <div className={`status-pill status-${scan?.status || "queued"}`}>
          {scan?.status || connectionState}
        </div>
      </div>

      {error ? <p className="error-text">{error}</p> : null}

      <div className="metric-grid">
        <Metric label="Attacks generated" value={metrics.attacksGenerated} />
        <Metric label="Violations found" value={metrics.violationsFound} />
        <Metric label="Patches applied" value={metrics.patchesApplied} />
        <Metric label="Rounds completed" value={metrics.roundsCompleted} />
      </div>

      <div className="panel">
        <div className="panel-heading">
          <h2>Violation rate progression</h2>
          <span>{formatPercent(metrics.currentRate)}</span>
        </div>
        <RateTimeline points={metrics.ratePoints} />
      </div>

      <div className="panel">
        <div className="panel-heading">
          <h2>Activity</h2>
          <span>{connectionState}</span>
        </div>
        <EventList events={events} />
      </div>

      {scan?.status === "completed" || scan?.status === "failed" ? (
        <div className="action-row">
          <button
            className="primary-button"
            onClick={() => navigate(`/report/${scanId}`)}
          >
            Open report
          </button>
        </div>
      ) : null}
    </section>
  );
}

function ReportPage({ scanId }) {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");

    getScan(scanId)
      .then((nextScan) => {
        if (active) {
          setScan(nextScan);
        }
      })
      .catch((scanError) => {
        if (active) {
          setError(scanError.message);
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [scanId]);

  const summary = scan?.summary;
  const findings = summary?.findings || [];
  const patches = summary?.patches_applied || [];
  const remainingRisks = summary?.remaining_risks || [];

  return (
    <section className="page-stack">
      <div className="page-title-row">
        <div>
          <p className="eyebrow">Report</p>
          <h1>{scanId}</h1>
        </div>
        <button onClick={() => navigate(`/live/${scanId}`)}>Back to live</button>
      </div>

      {loading ? <p className="muted-text">Loading report...</p> : null}
      {error ? <p className="error-text">{error}</p> : null}

      {scan ? (
        <>
          <div className="metric-grid">
            <Metric
              label="Initial violation rate"
              value={formatPercent(summary?.initial_violation_rate)}
            />
            <Metric
              label="Final violation rate"
              value={formatPercent(summary?.final_violation_rate)}
            />
            <Metric label="Remaining risks" value={remainingRisks.length} />
            <Metric label="Patches applied" value={patches.length} />
          </div>

          <div className="report-grid">
            <div className="panel">
              <div className="panel-heading">
                <h2>Category breakdown</h2>
              </div>
              <FindingTable findings={findings} />
            </div>

            <div className="panel">
              <div className="panel-heading">
                <h2>Remaining risks</h2>
              </div>
              {remainingRisks.length ? (
                <ul className="risk-list">
                  {remainingRisks.map((risk) => (
                    <li key={risk}>{risk}</li>
                  ))}
                </ul>
              ) : (
                <p className="muted-text">No remaining risks reported.</p>
              )}
            </div>
          </div>

          <div className="panel">
            <div className="panel-heading">
              <h2>Final markdown report</h2>
              <span>{scan.status}</span>
            </div>
            <pre className="markdown-report">
              {scan.markdown_report || "Report is not available yet."}
            </pre>
          </div>
        </>
      ) : null}
    </section>
  );
}

function Metric({ label, value }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function RateTimeline({ points }) {
  if (!points.length) {
    return <p className="muted-text">Waiting for rate data.</p>;
  }

  return (
    <ol className="rate-list">
      {points.map((point) => (
        <li key={point.label}>
          <div className="rate-row">
            <span>{point.label}</span>
            <strong>{formatPercent(point.value)}</strong>
          </div>
          <div className="rate-track" aria-hidden="true">
            <span style={{ width: `${Math.max(2, point.value * 100)}%` }} />
          </div>
        </li>
      ))}
    </ol>
  );
}

function EventList({ events }) {
  if (!events.length) {
    return <p className="muted-text">Waiting for scan activity.</p>;
  }

  return (
    <ol className="event-list">
      {events.map((event) => (
        <li key={event.event_id}>
          <span className="event-type">{humanize(event.type)}</span>
          <span className="event-time">{formatTime(event.timestamp)}</span>
          <EventDetail event={event} />
        </li>
      ))}
    </ol>
  );
}

function EventDetail({ event }) {
  const data = event.data || {};

  if (event.type === "attack_generated") {
    return (
      <p>
        {data.category} attack generated: {data.attack_id}
      </p>
    );
  }

  if (event.type === "violation_found") {
    return (
      <p>
        {data.category} violation on {data.attack_id}
        {data.severity ? `, ${data.severity} severity` : ""}
      </p>
    );
  }

  if (event.type === "patch_applied") {
    return (
      <p>
        Patch {data.patch_id} applied for {data.category}
      </p>
    );
  }

  if (event.type === "round_completed") {
    return (
      <p>
        Round {data.round_index} completed with{" "}
        {formatPercent(data.estimated_violation_rate)} estimated risk remaining
      </p>
    );
  }

  if (event.type === "scan_completed") {
    return (
      <p>
        Final violation rate: {formatPercent(data.final_violation_rate)}
      </p>
    );
  }

  if (event.type === "scan_failed") {
    return <p>{data.error || "Scan failed."}</p>;
  }

  return <p>{JSON.stringify(data)}</p>;
}

function FindingTable({ findings }) {
  if (!findings.length) {
    return <p className="muted-text">No findings available.</p>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Violations</th>
            <th>Rate</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr key={finding.category}>
              <td>{finding.category}</td>
              <td>
                {finding.violations}/{finding.total}
              </td>
              <td>{formatPercent(finding.violation_rate)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function buildLiveMetrics(events, scan) {
  const scanCompleted = [...events]
    .reverse()
    .find((event) => event.type === "scan_completed");
  const roundEvents = events.filter((event) => event.type === "round_completed");
  const summary = scan?.summary || {};
  const initialRate =
    summary.initial_violation_rate ?? scanCompleted?.data?.initial_violation_rate;
  const finalRate =
    summary.final_violation_rate ?? scanCompleted?.data?.final_violation_rate;
  const ratePoints = [];

  if (typeof initialRate === "number") {
    ratePoints.push({ label: "Initial", value: initialRate });
  }

  roundEvents.forEach((event) => {
    if (typeof event.data?.estimated_violation_rate === "number") {
      ratePoints.push({
        label: `Round ${event.data.round_index}`,
        value: event.data.estimated_violation_rate
      });
    }
  });

  if (typeof finalRate === "number") {
    ratePoints.push({ label: "Final", value: finalRate });
  }

  return {
    attacksGenerated: events.filter((event) => event.type === "attack_generated")
      .length,
    violationsFound: events.filter((event) => event.type === "violation_found")
      .length,
    patchesApplied: events.filter((event) => event.type === "patch_applied").length,
    roundsCompleted: roundEvents.length,
    ratePoints,
    currentRate: ratePoints.length ? ratePoints[ratePoints.length - 1].value : 0
  };
}

function parseSsePayload(payload) {
  try {
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

function formatPercent(value) {
  if (typeof value !== "number") {
    return "n/a";
  }
  return `${(value * 100).toFixed(1)}%`;
}

function formatTime(value) {
  if (!value) {
    return "";
  }
  return new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function humanize(value) {
  return value.replaceAll("_", " ");
}

function readRoute() {
  const hash = window.location.hash.replace(/^#\/?/, "");
  const [page, scanId] = hash.split("/");
  return {
    page: page || "setup",
    scanId: scanId || ""
  };
}

function navigate(path) {
  window.location.hash = path;
}

createRoot(document.getElementById("root")).render(<App />);
