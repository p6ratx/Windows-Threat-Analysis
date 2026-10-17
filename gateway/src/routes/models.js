import { Router } from 'express';
import {
  createModel,
  listModels,
  getModel,
  updateModel,
  deleteModel,
  addAsset,
  addActor,
  addBoundary,
  addScenario,
  addMitigation
} from '../services/models.js';
import { asyncHandler, asId, HttpError } from '../util/safe.js';

export function modelsRouter(db) {
  const r = Router();

  r.get(
    '/',
    asyncHandler(async (_req, res) => res.json(listModels(db)))
  );

  r.post(
    '/',
    asyncHandler(async (req, res) => res.status(201).json(createModel(db, req.body || {})))
  );

  r.get(
    '/:id',
    asyncHandler(async (req, res) => {
      const m = getModel(db, asId(req.params.id));
      if (!m) throw new HttpError(404, 'not found', 'not_found');
      res.json(m);
    })
  );

  r.patch(
    '/:id',
    asyncHandler(async (req, res) => {
      const m = updateModel(db, asId(req.params.id), req.body || {});
      if (!m) throw new HttpError(404, 'not found', 'not_found');
      res.json(m);
    })
  );

  r.delete(
    '/:id',
    asyncHandler(async (req, res) => {
      if (!deleteModel(db, asId(req.params.id))) throw new HttpError(404, 'not found', 'not_found');
      res.status(204).end();
    })
  );

  function requireModel(req) {
    const id = asId(req.params.id);
    if (!getModel(db, id)) throw new HttpError(404, 'not found', 'not_found');
    return id;
  }

  r.post(
    '/:id/assets',
    asyncHandler(async (req, res) => {
      res.status(201).json(addAsset(db, requireModel(req), req.body || {}));
    })
  );

  r.post(
    '/:id/actors',
    asyncHandler(async (req, res) => {
      res.status(201).json(addActor(db, requireModel(req), req.body || {}));
    })
  );

  r.post(
    '/:id/boundaries',
    asyncHandler(async (req, res) => {
      res.status(201).json(addBoundary(db, requireModel(req), req.body || {}));
    })
  );

  r.post(
    '/:id/scenarios',
    asyncHandler(async (req, res) => {
      res.status(201).json(addScenario(db, requireModel(req), req.body || {}));
    })
  );

  r.post(
    '/:id/mitigations',
    asyncHandler(async (req, res) => {
      res.status(201).json(addMitigation(db, requireModel(req), req.body || {}));
    })
  );

  return r;
}
