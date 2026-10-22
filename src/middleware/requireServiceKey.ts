import type { RequestHandler } from 'express';
import { config } from '../config';
import { HttpError } from '../errors/httpError';

export const requireServiceKey: RequestHandler = (req, res, next) => {
  const providedKey = req.header('x-service-key');

  if (providedKey === undefined || providedKey !== config.serviceKey) {
    next(new HttpError(401, 'Invalid service key'));
    return;
  }

  next();
};
