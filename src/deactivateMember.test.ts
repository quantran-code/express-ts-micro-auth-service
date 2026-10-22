import { hashSync } from 'bcrypt';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';

import app from './app';
import { config } from './config';
import { createUser, resetUsers } from './repositories/userRepository';

interface ApiErrorBody {
  error: string;
}

interface DeactivateSuccessBody {
  id: number;
  memberId: number | null;
  email: string;
  role: string;
  active: boolean;
}

interface LoginSuccessBody {
  accessToken: string;
  tokenType: string;
  role: string;
}

const MEMBER_ID = 42;
const MEMBER_EMAIL = 'member@library.test';
const MEMBER_PASSWORD = 'MemberPassword123!';
const PASSWORD_SALT_ROUNDS = 10;

const memberServiceMember = { id: MEMBER_ID, name: 'Member', email: MEMBER_EMAIL, active: false };

let fetchMock: Mock<typeof fetch>;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function deactivateRequest(memberId: string, role?: string) {
  const base = request(app)
    .post(`/auth/members/${memberId}/deactivate`)
    .set('x-service-key', config.serviceKey);

  return role === undefined ? base : base.set('x-user-role', role);
}

function loginMember() {
  return request(app)
    .post('/auth/login')
    .set('x-service-key', config.serviceKey)
    .send({ email: MEMBER_EMAIL, password: MEMBER_PASSWORD });
}

beforeEach(() => {
  resetUsers();
  createUser({
    memberId: MEMBER_ID,
    email: MEMBER_EMAIL,
    passwordHash: hashSync(MEMBER_PASSWORD, PASSWORD_SALT_ROUNDS),
    role: 'member',
  });
  fetchMock = vi.fn<typeof fetch>();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('POST /auth/members/:id/deactivate', () => {
  it('refuses the call when no caller identity is forwarded', async () => {
    const res = await deactivateRequest(String(MEMBER_ID));

    expect(res.status).toBe(403);
    expect((res.body as ApiErrorBody).error).toBe('Only a librarian can deactivate an account');
    expect(fetchMock).not.toHaveBeenCalled();

    const stillActive = await loginMember();
    expect(stillActive.status).toBe(200);
  });

  it('refuses the call when the forwarded identity is not a librarian', async () => {
    const res = await deactivateRequest(String(MEMBER_ID), 'member');

    expect(res.status).toBe(403);
    expect((res.body as ApiErrorBody).error).toBe('Only a librarian can deactivate an account');
    expect(fetchMock).not.toHaveBeenCalled();

    const stillActive = await loginMember();
    expect(stillActive.status).toBe(200);
  });

  it('deactivates the member in member-service and answers with the updated user', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, memberServiceMember));

    const res = await deactivateRequest(String(MEMBER_ID), 'librarian');

    expect(res.status).toBe(200);
    const body = res.body as DeactivateSuccessBody;
    expect(body).toEqual({
      id: 2,
      memberId: MEMBER_ID,
      email: MEMBER_EMAIL,
      role: 'member',
      active: false,
    });
    expect(body).not.toHaveProperty('passwordHash');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe(
      `${config.memberServiceUrl}/internal/members/${MEMBER_ID}/active`,
    );
    expect(init?.method).toBe('PATCH');
    expect(init?.headers).toEqual({
      'content-type': 'application/json',
      'x-service-key': config.serviceKey,
    });
    expect(JSON.parse(String(init?.body))).toEqual({ active: false });

    const login = await loginMember();
    expect(login.status).toBe(401);
    expect((login.body as ApiErrorBody).error).toBe('Account is deactivated');
    expect(login.body).not.toHaveProperty('accessToken');
  });

  it('answers 404 without calling member-service when no local user has that memberId', async () => {
    const res = await deactivateRequest('999', 'librarian');

    expect(res.status).toBe(404);
    expect((res.body as ApiErrorBody).error).toBe('Member not found');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('answers 404 for a malformed member id', async () => {
    const res = await deactivateRequest('abc', 'librarian');

    expect(res.status).toBe(404);
    expect((res.body as ApiErrorBody).error).toBe('Member not found');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('propagates a member-service 404 and leaves the local user active', async () => {
    fetchMock.mockResolvedValue(jsonResponse(404, { error: 'Member not found' }));

    const res = await deactivateRequest(String(MEMBER_ID), 'librarian');

    expect(res.status).toBe(404);
    expect((res.body as ApiErrorBody).error).toBe('Member not found');

    const stillActive = await loginMember();
    expect(stillActive.status).toBe(200);
    expect((stillActive.body as LoginSuccessBody).tokenType).toBe('Bearer');
  });

  it('answers 502 when member-service cannot be reached and leaves the local user active', async () => {
    fetchMock.mockRejectedValue(new TypeError('fetch failed'));

    const res = await deactivateRequest(String(MEMBER_ID), 'librarian');

    expect(res.status).toBe(502);
    expect((res.body as ApiErrorBody).error).toBe('Unable to reach member-service');

    const stillActive = await loginMember();
    expect(stillActive.status).toBe(200);
    expect((stillActive.body as LoginSuccessBody).tokenType).toBe('Bearer');
  });
});
