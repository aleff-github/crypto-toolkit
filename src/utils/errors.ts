export interface UserFacingErrorDetails {
  reason?: string;
  expected?: string;
  hint?: string;
}

export class UserFacingError extends Error {
  readonly details?: UserFacingErrorDetails;

  constructor(message: string, details?: UserFacingErrorDetails) {
    super(message);
    this.name = 'UserFacingError';
    this.details = details;
  }
}

export function toUserMessage(error: unknown): string {
  if (error instanceof UserFacingError) {
    const details = error.details;
    if (!details || (!details.reason && !details.expected && !details.hint)) {
      return error.message;
    }

    const lines = [error.message];
    if (details.reason) lines.push(`Reason: ${details.reason}`);
    if (details.expected) lines.push(`Expected: ${details.expected}`);
    if (details.hint) lines.push(`Hint: ${details.hint}`);
    return lines.join('\n');
  }

  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message;
  }

  return 'The operation failed because of an unknown error.';
}
