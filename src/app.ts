import express, { Request, Response, NextFunction } from 'express';
import type { RequestHandler } from 'express';
import { HttpError } from './errors/httpError';
import { requireServiceKey } from './middleware/requireServiceKey';
import { authRouter } from './routes/auth';

const app = express();

app.use(express.json());

app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'ok', service: 'auth-service' });
});

const serviceKeyGate: RequestHandler = (req, res, next) => {
  if (req.path === '/health') {
    next();
    return;
  }

  requireServiceKey(req, res, next);
};

app.use(serviceKeyGate);
app.use('/auth', authRouter);

app.use((req: Request, res: Response) => {
  res.status(404).json({ error: 'Not Found' });
});

// eslint-disable-next-line no-unused-vars
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  const status = err instanceof HttpError ? err.status : 500;
  res.status(status).json({ error: err.message || 'Internal Server Error' });
});

export default app;
