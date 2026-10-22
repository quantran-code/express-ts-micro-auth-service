import { config } from '../config';
import { HttpError } from '../errors/httpError';

export interface MemberServiceMember {
  id: number;
  name: string;
  email: string;
}

export interface CreateMemberInput {
  name: string;
  email: string;
}

interface MemberServiceErrorBody {
  error?: string;
}

function readErrorMessage(body: unknown): string | undefined {
  if (body !== null && typeof body === 'object' && 'error' in body) {
    const { error } = body as MemberServiceErrorBody;
    if (typeof error === 'string' && error.length > 0) {
      return error;
    }
  }
  return undefined;
}

async function readJsonBody(response: Awaited<ReturnType<typeof fetch>>): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

export async function createMember(input: CreateMemberInput): Promise<MemberServiceMember> {
  let response: Awaited<ReturnType<typeof fetch>>;
  try {
    response = await fetch(`${config.memberServiceUrl}/internal/members`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-service-key': config.serviceKey,
      },
      body: JSON.stringify({ name: input.name, email: input.email }),
    });
  } catch {
    throw new HttpError(502, 'Unable to reach member-service');
  }

  if (!response.ok) {
    const body = await readJsonBody(response);
    throw new HttpError(
      response.status,
      readErrorMessage(body) ?? 'member-service request failed',
    );
  }

  const created = (await response.json()) as MemberServiceMember;
  return created;
}

export async function deactivateMember(memberId: number): Promise<MemberServiceMember> {
  let response: Awaited<ReturnType<typeof fetch>>;
  try {
    response = await fetch(`${config.memberServiceUrl}/internal/members/${memberId}/active`, {
      method: 'PATCH',
      headers: {
        'content-type': 'application/json',
        'x-service-key': config.serviceKey,
      },
      body: JSON.stringify({ active: false }),
    });
  } catch {
    throw new HttpError(502, 'Unable to reach member-service');
  }

  if (!response.ok) {
    const body = await readJsonBody(response);
    throw new HttpError(
      response.status,
      readErrorMessage(body) ?? 'member-service request failed',
    );
  }

  const updated = (await response.json()) as MemberServiceMember;
  return updated;
}
