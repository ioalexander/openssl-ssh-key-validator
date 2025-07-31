export enum PrivateKeyValidationError {
  CANT_BE_EMPTY = "CANT_BE_EMPTY",
  INVALID_HEADER = "INVALID_HEADER",
  INVALID_FOOTER = "INVALID_FOOTER",
  INVALID_BODY_ERROR = "INVALID_BODY_ERROR",
}

export type PrivateKeyValidationErrorType = `${PrivateKeyValidationError}`;

export type PrivateKeyValidationResult = {
  isValid: boolean;
  message: string;
  errorType?: PrivateKeyValidationErrorType;
  errorPosition?: {
    line: number;
    character: number;
  };
};
