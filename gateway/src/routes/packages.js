import { Router } from 'express';
import {
  createPackage,
  listPackages,
  getPackage,
  updatePackageStatus,
  exportPackage
} from '../services/packages.js';
import { asyncHandler, asId, asEnum, HttpError } from '../util/safe.js';

export function packagesRouter(db) {
  const r = Router();

  r.get(
    '/',
    asyncHandler(async (_req, res) => res.json(listPackages(db)))
  );

  r.post(
    '/',
    asyncHandler(async (req, res) => res.status(201).json(createPackage(db, req.body || {})))
  );

  r.get(
    '/:id',
    asyncHandler(async (req, res) => {
      const p = getPackage(db, asId(req.params.id));
      if (!p) throw new HttpError(404, 'not found', 'not_found');
      res.json(p);
    })
  );

  r.post(
    '/:id/status',
    asyncHandler(async (req, res) => {
      const p = updatePackageStatus(db, asId(req.params.id), req.body?.status, {
        channel: req.body?.channel,
        note: req.body?.note
      });
      if (!p) throw new HttpError(404, 'not found', 'not_found');
      res.json(p);
    })
  );

  r.get(
    '/:id/export',
    asyncHandler(async (req, res) => {
      const out = exportPackage(db, asId(req.params.id));
      if (!out) throw new HttpError(404, 'not found', 'not_found');
      const format = asEnum(req.query.format || 'json', ['json', 'md'], 'json');
      if (format === 'md') {
        res.type('text/markdown; charset=utf-8').send(out.markdown);
        return;
      }
      res.json({ ...out.json, briefing_markdown: out.markdown });
    })
  );

  return r;
}
