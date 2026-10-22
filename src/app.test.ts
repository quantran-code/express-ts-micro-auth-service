import { createHmac } from 'node:crypto';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import { compare } from 'bcrypt';

vi.mock('bcrypt', async (importOriginal) => {
  const actual = await importOriginal<typeof import('bcrypt')>();
  return {
    ...actual,
    compare: vi.fn(actual.compare),
  };
});

import app from './app';
import { config } from './config';
import { DUMMY_PASSWORD_HASH } from './lib/passwords';
import { createUser, resetUsers } from './repositories/userRepository';

interface ApiErrorBody {
  error: string;
}

interface RegisterSuccessBody {
  id: number;
  memberId: number | null;
  name: string;
  email: string;
  role: string;
}

interface LoginSuccessBody {
  accessToken: string;
  tokenType: string;
  role: string;
}

interface TokenHeader {
  alg: string;
  typ: string;
}

interface TokenPayload {
  sub: number;
  role: string;
  memberId: number | null;
  iat: number;
  exp: number;
}

let fetchMock: Mock<typeof fetch>;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function decodeSegment<T>(segment: string): T {
  const json = Buffer.from(segment, 'base64url').toString('utf8');
  return JSON.parse(json) as T;
}

function registerBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: 'Ada',
    email: 'ada@library.test',
    password: 'Password123!',
    ...overrides,
  };
}

const memberServiceMember = { id: 42, name: 'Ada', email: 'ada@library.test' };

beforeEach(() => {
  vi.clearAllMocks();
  resetUsers();
  fetchMock = vi.fn<typeof fetch>();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('service key gate', () => {
  it('lets GET /health through without a key', async () => {
    const res = await request(app).get('/health');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok', service: 'auth-service' });
  });

  it('rejects POST /auth/register without a key before any route logic runs', async () => {
    const res = await request(app).post('/auth/register').send(registerBody());

    expect(res.status).toBe(401);
    expect((res.body as ApiErrorBody).error).toBe('Invalid service key');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects POST /auth/login with a wrong key', async () => {
    const res = await request(app)
      .post('/auth/login')
      .set('x-service-key', 'wrong-key')
      .send({ email: 'librarian@library.test', password: 'Librarian123!' });

    expect(res.status).toBe(401);
    expect((res.body as ApiErrorBody).error).toBe('Invalid service key');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects an unknown path without a key and answers 404 with one', async () => {
    const withoutKey = await request(app).get('/unknown');
    expect(withoutKey.status).toBe(401);

    const withKey = await request(app).get('/unknown').set('x-service-key', config.serviceKey);
    expect(withKey.status).toBe(404);
  });
});

describe('POST /auth/register', () => {
  it('rejects a blank name without calling member-service', async () => {
    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .send(registerBody({ name: '   ' }));

    expect(res.status).toBe(400);
    expect((res.body as ApiErrorBody).error).toBe('Name is required');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects an invalid email without calling member-service', async () => {
    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .send(registerBody({ email: 'not-an-email' }));

    expect(res.status).toBe(400);
    expect((res.body as ApiErrorBody).error).toBe('A valid email is required');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a password shorter than 8 characters without calling member-service', async () => {
    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .send(registerBody({ password: 'short' }));

    expect(res.status).toBe(400);
    expect((res.body as ApiErrorBody).error).toBe('Password must be at least 8 characters');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a role outside member/librarian without calling member-service', async () => {
    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .send(registerBody({ role: 'admin' }));

    expect(res.status).toBe(400);
    expect((res.body as ApiErrorBody).error).toBe("Role must be either 'member' or 'librarian'");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses a librarian account when no caller identity is forwarded', async () => {
    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .send(registerBody({ role: 'librarian' }));

    expect(res.status).toBe(403);
    expect((res.body as ApiErrorBody).error).toBe(
      'Only a librarian can create a librarian account',
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses a librarian account when the forwarded identity is not a librarian', async () => {
    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .set('x-user-role', 'member')
      .send(registerBody({ role: 'librarian' }));

    expect(res.status).toBe(403);
    expect((res.body as ApiErrorBody).error).toBe(
      'Only a librarian can create a librarian account',
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('creates a member by calling member-service and responds 201 without the password hash', async () => {
    fetchMock.mockResolvedValue(jsonResponse(201, memberServiceMember));

    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .send(registerBody());

    expect(res.status).toBe(201);
    const body = res.body as RegisterSuccessBody;
    expect(body).toEqual({
      id: 2,
      memberId: 42,
      name: 'Ada',
      email: 'ada@library.test',
      role: 'member',
    });
    expect(body).not.toHaveProperty('passwordHash');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    const requestUrl = String(url);
    expect(requestUrl).toBe(`${config.memberServiceUrl}/internal/members`);
    expect(requestUrl.endsWith('/internal/members')).toBe(true);

    expect(init?.method).toBe('POST');
    expect(init?.headers).toEqual({
      'content-type': 'application/json',
      'x-service-key': config.serviceKey,
    });
    expect(JSON.parse(String(init?.body))).toEqual({
      name: 'Ada',
      email: 'ada@library.test',
    });
  });

  it('creates a librarian account when the caller identity is a librarian', async () => {
    fetchMock.mockResolvedValue(jsonResponse(201, memberServiceMember));

    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .set('x-user-role', 'librarian')
      .send(registerBody({ role: 'librarian' }));

    expect(res.status).toBe(201);
    expect((res.body as RegisterSuccessBody).role).toBe('librarian');
  });

  it('rejects an already registered email ignoring case without calling member-service', async () => {
    createUser({
      memberId: 7,
      email: 'reader@library.test',
      passwordHash: DUMMY_PASSWORD_HASH,
      role: 'member',
    });

    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .send(registerBody({ email: 'READER@Library.test' }));

    expect(res.status).toBe(409);
    expect((res.body as ApiErrorBody).error).toBe('Email already registered');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('answers 502 when member-service cannot be reached', async () => {
    fetchMock.mockRejectedValue(new TypeError('fetch failed'));

    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .send(registerBody());

    expect(res.status).toBe(502);
    expect((res.body as ApiErrorBody).error).toBe('Unable to reach member-service');
  });

  it('propagates the exact status and message from member-service', async () => {
    fetchMock.mockResolvedValue(jsonResponse(418, { error: 'Teapot' }));

    const res = await request(app)
      .post('/auth/register')
      .set('x-service-key', config.serviceKey)
      .send(registerBody());

    expect(res.status).toBe(418);
    expect((res.body as ApiErrorBody).error).toBe('Teapot');
  });
});

describe('POST /auth/login', () => {
  it('issues an HS256 token with the expected claims for the seeded librarian', async () => {
    const res = await request(app)
      .post('/auth/login')
      .set('x-service-key', config.serviceKey)
      .send({ email: 'librarian@library.test', password: 'Librarian123!' });

    expect(res.status).toBe(200);
    const body = res.body as LoginSuccessBody;
    expect(body.tokenType).toBe('Bearer');
    expect(body.role).toBe('librarian');

    const segments = body.accessToken.split('.');
    expect(segments).toHaveLength(3);

    const [encodedHeader, encodedPayload, signature] = segments;
    expect(decodeSegment<TokenHeader>(encodedHeader)).toEqual({ alg: 'HS256', typ: 'JWT' });

    const payload = decodeSegment<TokenPayload>(encodedPayload);
    expect(payload.sub).toBe(1);
    expect(payload.role).toBe('librarian');
    expect(payload.memberId).toBeNull();
    expect(typeof payload.iat).toBe('number');
    expect(payload.exp - payload.iat).toBe(3600);
    expect(payload.exp - payload.iat).toBe(config.accessTokenTtlSeconds);

    const expectedSignature = createHmac('sha256', config.jwtSecret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64url');
    expect(signature).toBe(expectedSignature);
  });

  it('still runs a bcrypt compare before rejecting an unknown email', async () => {
    const compareMock = vi.mocked(compare);

    const res = await request(app)
      .post('/auth/login')
      .set('x-service-key', config.serviceKey)
      .send({ email: 'nobody@library.test', password: 'Password123!' });

    expect(res.status).toBe(401);
    expect((res.body as ApiErrorBody).error).toBe('Invalid credentials');
    expect(compareMock).toHaveBeenCalledTimes(1);
  });

  it('rejects a known email with the wrong password', async () => {
    const res = await request(app)
      .post('/auth/login')
      .set('x-service-key', config.serviceKey)
      .send({ email: 'librarian@library.test', password: 'WrongPassword123!' });

    expect(res.status).toBe(401);
    expect((res.body as ApiErrorBody).error).toBe('Invalid credentials');
  });

  it('answers 400 for a body without an email or without a password', async () => {
    const withoutEmail = await request(app)
      .post('/auth/login')
      .set('x-service-key', config.serviceKey)
      .send({ password: 'Librarian123!' });

    expect(withoutEmail.status).toBe(400);

    const withoutPassword = await request(app)
      .post('/auth/login')
      .set('x-service-key', config.serviceKey)
      .send({ email: 'librarian@library.test' });

    expect(withoutPassword.status).toBe(400);
  });
});
