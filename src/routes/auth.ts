import { Router } from 'express';
import type { RequestHandler } from 'express';
import { createMember, deactivateMember } from '../clients/memberService';
import { HttpError } from '../errors/httpError';
import { DUMMY_PASSWORD_HASH, hashPassword, verifyPassword } from '../lib/passwords';
import { signAccessToken } from '../lib/tokens';
import { createUser, findUserByEmail, findUserByMemberId } from '../repositories/userRepository';
import type { UserRole } from '../repositories/userRepository';

export interface RegisterBody {
  name?: string;
  email?: string;
  password?: string;
  role?: string;
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 8;
const DEFAULT_ROLE: UserRole = 'member';
const ALLOWED_ROLES: readonly string[] = ['member', 'librarian'];

function isAllowedRole(value: string): value is UserRole {
  return ALLOWED_ROLES.includes(value);
}

export const registerHandler: RequestHandler<Record<string, never>, unknown, RegisterBody> = async (
  req,
  res,
  next,
) => {
  try {
    const body: RegisterBody = req.body ?? {};
    const { name, email, password, role: requestedRole } = body;

    if (typeof name !== 'string' || name.trim().length === 0) {
      throw new HttpError(400, 'Name is required');
    }

    if (typeof email !== 'string' || !EMAIL_PATTERN.test(email.trim())) {
      throw new HttpError(400, 'A valid email is required');
    }

    if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
      throw new HttpError(400, `Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
    }

    let role: UserRole = DEFAULT_ROLE;
    if (requestedRole !== undefined) {
      if (typeof requestedRole !== 'string' || !isAllowedRole(requestedRole)) {
        throw new HttpError(400, "Role must be either 'member' or 'librarian'");
      }
      role = requestedRole;
    }

    if (role === 'librarian' && req.header('x-user-role') !== 'librarian') {
      throw new HttpError(403, 'Only a librarian can create a librarian account');
    }

    const trimmedEmail = email.trim();
    if (findUserByEmail(trimmedEmail) !== undefined) {
      throw new HttpError(409, 'Email already registered');
    }

    const member = await createMember({ name: name.trim(), email: trimmedEmail });
    const passwordHash = await hashPassword(password);
    const user = createUser({
      memberId: member.id,
      email: member.email,
      passwordHash,
      role,
    });

    res.status(201).json({
      id: user.id,
      memberId: user.memberId,
      name: name.trim(),
      email: user.email,
      role: user.role,
      active: user.active,
    });
  } catch (err) {
    next(err);
  }
};

export interface LoginBody {
  email?: string;
  password?: string;
}

export const loginHandler: RequestHandler<Record<string, never>, unknown, LoginBody> = async (
  req,
  res,
  next,
) => {
  try {
    const body: LoginBody = req.body ?? {};
    const { email, password } = body;

    if (typeof email !== 'string' || email.trim().length === 0) {
      throw new HttpError(400, 'Email is required');
    }

    if (typeof password !== 'string' || password.length === 0) {
      throw new HttpError(400, 'Password is required');
    }

    const user = findUserByEmail(email);

    if (user === undefined) {
      // Compare against the dummy hash so an unknown email costs the same as a wrong password.
      await verifyPassword(password, DUMMY_PASSWORD_HASH);
      throw new HttpError(401, 'Invalid credentials');
    }

    const passwordMatches = await verifyPassword(password, user.passwordHash);
    if (!passwordMatches) {
      throw new HttpError(401, 'Invalid credentials');
    }

    if (!user.active) {
      throw new HttpError(401, 'Account is deactivated');
    }

    const accessToken = signAccessToken(user);

    res.status(200).json({
      accessToken,
      tokenType: 'Bearer',
      role: user.role,
    });
  } catch (err) {
    next(err);
  }
};

export interface DeactivateMemberParams {
  id: string;
}

export const deactivateMemberHandler: RequestHandler<DeactivateMemberParams> = async (
  req,
  res,
  next,
) => {
  try {
    if (req.header('x-user-role') !== 'librarian') {
      throw new HttpError(403, 'Only a librarian can deactivate an account');
    }

    const memberId = Number(req.params.id);
    if (!Number.isInteger(memberId) || memberId <= 0) {
      throw new HttpError(404, 'Member not found');
    }

    const user = findUserByMemberId(memberId);
    if (user === undefined) {
      throw new HttpError(404, 'Member not found');
    }

    await deactivateMember(memberId);

    user.active = false;

    res.status(200).json({
      id: user.id,
      memberId: user.memberId,
      email: user.email,
      role: user.role,
      active: user.active,
    });
  } catch (err) {
    next(err);
  }
};

export const authRouter = Router();

authRouter.post('/register', registerHandler);
authRouter.post('/login', loginHandler);
authRouter.post('/members/:id/deactivate', deactivateMemberHandler);
