import { OperationResult } from '../commands/types';

export type SmartKind =
  | 'jwt'
  | 'json'
  | 'base64'
  | 'base64url'
  | 'hex'
  | 'urlEncoded'
  | 'htmlEntities'
  | 'unixTimestamp'
  | 'queryString'
  | 'cookie'
  | 'setCookie'
  | 'basicAuth'
  | 'powershellEncodedCommand'
  | 'uuid'
  | 'url'
  | 'pem'
  | 'certificate'
  | 'privateKey'
  | 'publicKey'
  | 'sshPublicKey'
  | 'hashLike'
  | 'passwordHash'
  | 'checksum'
  | 'jwe'
  | 'joseHeader'
  | 'paseto'
  | 'fernet'
  | 'otpauth'
  | 'openpgp'
  | 'secret'
  | 'opensslSalted'
  | 'ansibleVault'
  | 'ageEncrypted'
  | 'asn1Der'
  | 'saml'
  | 'webFrameworkToken';

export type CandidateSeverity = 'info' | 'warning' | 'danger';

export interface SmartDecodeCandidate {
  kind: SmartKind;
  label: string;
  confidence: number;
  input: string;
  output: string;
  preview: string;
  warnings: string[];
  language?: OperationResult['language'];
  metadata?: Record<string, unknown>;
  /** Human-readable scoring / detection reasons. */
  reasons?: string[];
  severity?: CandidateSeverity;
}

export interface SmartDecodeOptions {
  minimumConfidence: number;
  maxCandidates: number;
  showLowConfidence: boolean;
}

export interface DetectorContext {
  originalInput: string;
  trimmedInput: string;
  compactInput: string;
}

export type SmartDetector = (context: DetectorContext) => SmartDecodeCandidate[];
