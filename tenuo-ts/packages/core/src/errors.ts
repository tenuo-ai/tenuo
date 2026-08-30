import type { TenuoErrorCode } from "./api.ts";

export class TenuoError extends Error {
  readonly code: TenuoErrorCode;

  constructor(code: TenuoErrorCode, message: string) {
    super(message);
    this.name = "TenuoError";
    this.code = code;
  }
}

export class TenuoConfigurationError extends TenuoError {
  constructor(message: string, code: TenuoErrorCode = "TENUO_CONFIGURATION") {
    super(code, message);
    this.name = "TenuoConfigurationError";
  }
}

export class AuthorizationDeniedError extends TenuoError {
  readonly field?: string;

  constructor(code: TenuoErrorCode, message: string, field?: string) {
    super(code, message);
    this.name = "AuthorizationDeniedError";
    if (field !== undefined) {
      this.field = field;
    }
  }
}

export class ApprovalRequiredError extends TenuoError {
  readonly tool: string;
  readonly required: number;
  readonly received: number;

  constructor(tool: string, required: number, received: number, message?: string) {
    super("TENUO_APPROVAL_REQUIRED", message ?? `Approval required for ${tool}`);
    this.name = "ApprovalRequiredError";
    this.tool = tool;
    this.required = required;
    this.received = received;
  }
}
