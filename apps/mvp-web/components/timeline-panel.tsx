"use client";

import { useEffect, useState, type ReactNode } from "react";
import { admin } from "../lib/api";

interface OperationEvent {
  sequence: string;
  intentId: string | null;
  eventType: string;
  actor: string;
  actorRole: string;
  payload: Record<string, unknown>;
  createdAt: string;
}

/** Append-only operation timeline. Payloads carry hashes and states, no secrets. */
export function TimelinePanel(): ReactNode {
  const [events, setEvents] = useState<OperationEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    admin("/timeline")
      .then((body) => setEvents(body.events))
      .catch(() => setError("LOAD_FAILED"));
  }, []);

  return (
    <section className="ol-card">
      <h2>Operation timeline</h2>
      {error !== null ? <p className="ol-error">{error}</p> : null}
      <table>
        <thead>
          <tr><th>#</th><th>Event</th><th>Actor</th><th>Details</th><th>Time</th></tr>
        </thead>
        <tbody data-testid="timeline-table">
          {events.map((event) => (
            <tr key={event.sequence}>
              <td>{event.sequence}</td>
              <td>{event.eventType}</td>
              <td>{event.actor} ({event.actorRole})</td>
              <td>{JSON.stringify(event.payload)}</td>
              <td>{new Date(event.createdAt).toISOString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {events.length === 0 ? <p className="ol-muted">No operations recorded yet.</p> : null}
    </section>
  );
}
