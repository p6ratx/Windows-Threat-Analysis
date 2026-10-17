import { Router } from 'express';
import { ingestEvent, ingestBatch, listEvents } from '../services/evidence.js';
import { asyncHandler, clampLimit, asString, asOptionalId, HttpError } from '../util/safe.js';

export function eventsRouter(db) {
  const r = Router();

  r.get(
    '/',
    asyncHandler(async (req, res) => {
      res.json(
        listEvents(db, {
          limit: clampLimit(req.query.limit, 100, 500),
          offset: Number(req.query.offset || 0),
          type: req.query.type ? asString(req.query.type, { max: 120 }) : undefined,
          host_id: req.query.host_id ? asString(req.query.host_id, { max: 128 }) : undefined
        })
      );
    })
  );

  r.post(
    '/ingest',
    asyncHandler(async (req, res) => {
      const scanRunId = asOptionalId(req.query.scan_run_id, 'scan_run_id');
      const body = req.body;
      if (Array.isArray(body)) {
        const events = ingestBatch(db, body, scanRunId);
        return res.status(201).json({ count: events.length, events });
      }
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'Expected event object or array');
      }
      const event = ingestEvent(db, body, { scanRunId });
      if (!event) {
        throw new HttpError(422, 'Synthetic/demo event rejected (set AEGIS_ALLOW_SYNTHETIC=1 to allow)', 'synthetic_rejected');
      }
      res.status(201).json(event);
    })
  );

  return r;
}
