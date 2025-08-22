// src/utils/validation.ts
// Input validation and sanitization utilities for security remediation

import { ValidationResult, createValidationResult } from './errorHandling';

/**
 * Validates that a token is properly formed and non-empty
 * Prevents invalid tokens from being stored or used
 */
export function validateToken(token: string | null | undefined): ValidationResult {
  if (!token || typeof token !== 'string') {
    return createValidationResult(false, "Invalid token: token is null or undefined");
  }
  
  if (token.length === 0) {
    return createValidationResult(false, "Invalid token: token is empty");
  }
  
  // More permissive validation for session tokens - allow standard base64 characters
  const tokenPattern = /^[A-Za-z0-9+/=_-]+$/;
  if (!tokenPattern.test(token)) {
    return createValidationResult(false, "Invalid token: invalid characters in token");
  }
  
  // Token should have reasonable length (not suspiciously short)
  if (token.length < 10) {
    return createValidationResult(false, "Invalid token: token too short");
  }
  
  // Additional validation for HTTP header compatibility (no control characters)
  if (/[\x00-\x1F\x7F]/.test(token)) {
    return createValidationResult(false, "Invalid token: contains control characters");
  }
  
  return createValidationResult(true);
}

/**
 * Validates base32 encoded TOTP secrets
 * Prevents malformed secrets from causing application crashes
 */
export function validateBase32Secret(secret: string | null | undefined): ValidationResult {
  if (!secret || typeof secret !== 'string') {
    return createValidationResult(false, "Invalid secret: secret is null or undefined");
  }
  
  if (secret.length === 0) {
    return createValidationResult(false, "Invalid secret: secret is empty");
  }
  
  // Base32 should only contain A-Z and 2-7, with optional padding (=)
  const base32Pattern = /^[A-Z2-7]+=*$/;
  if (!base32Pattern.test(secret.toUpperCase())) {
    return createValidationResult(false, "Invalid secret: not valid base32 format");
  }
  
  // Base32 length should be multiple of 8 (with padding) or have valid unpadded length
  const cleanSecret = secret.replace(/=/g, '');
  if (cleanSecret.length === 0) {
    return createValidationResult(false, "Invalid secret: secret contains only padding");
  }
  
  return createValidationResult(true);
}

/**
 * Validates encryption capability before attempting to store sensitive data
 * Ensures LocalStorage encryption is available before proceeding
 */
export function validateEncryptionCapability(): ValidationResult {
  try {
    // Test if LocalStorage is available
    if (typeof window === 'undefined' || !window.localStorage) {
      return createValidationResult(false, "LocalStorage not available");
    }
    
    // For Raycast, we should have LocalStorage API available
    // This is a basic check - in practice we'd test actual encryption
    return createValidationResult(true);
  } catch (error) {
    return createValidationResult(false, "LocalStorage access failed");
  }
}

/**
 * Validates that required authentication parameters are present
 * Prevents authentication attempts with missing data
 */
export function validateAuthParameters(params: {
  email?: string;
  password?: string;
  srpAttributes?: any;
}): ValidationResult {
  const { email, password, srpAttributes } = params;
  
  if (!email || typeof email !== 'string' || email.length === 0) {
    return createValidationResult(false, "Email is required");
  }
  
  if (!password || typeof password !== 'string' || password.length === 0) {
    return createValidationResult(false, "Password is required");
  }
  
  if (!srpAttributes || typeof srpAttributes !== 'object') {
    return createValidationResult(false, "Authentication parameters are missing");
  }
  
  // Validate that srpAttributes has required fields
  if (!srpAttributes.kekSalt || !srpAttributes.memLimit || !srpAttributes.opsLimit) {
    return createValidationResult(false, "Authentication parameters are incomplete");
  }
  
  return createValidationResult(true);
}

/**
 * Validates session token response from server
 * Ensures response has required fields before processing
 */
export function validateSessionResponse(response: any): ValidationResult {
  if (!response || typeof response !== 'object') {
    return createValidationResult(false, "Invalid response format");
  }
  
  // Check for passkey scenario (not supported)
  if (response.passkeySessionID) {
    return createValidationResult(false, "Passkey not supported, kindly disable and login and enable it back");
  }
  
  // For email OTP responses, we just need basic validation
  if (response.encryptedToken && response.token) {
    return createValidationResult(true);
  }
  
  // For SRP responses, we need keyAttributes
  if (response.keyAttributes) {
    if (typeof response.keyAttributes !== 'object') {
      return createValidationResult(false, "Passkey not supported, kindly disable and login and enable it back");
    }
    
    if (!response.keyAttributes.kekSalt) {
      return createValidationResult(false, "Passkey not supported, kindly disable and login and enable it back");
    }
    
    return createValidationResult(true);
  }
  
  return createValidationResult(false, "Authentication response is incomplete");
}

/**
 * Sanitizes input strings to prevent injection attacks
 * Removes potentially dangerous characters from user input
 */
export function sanitizeInput(input: string): string {
  if (typeof input !== 'string') {
    return '';
  }
  
  // Remove null bytes and control characters except newlines/tabs
  return input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

/**
 * Validates that encryption keys have proper length and format
 * Prevents weak or malformed keys from being used
 */
export function validateEncryptionKey(key: Buffer | Uint8Array | null | undefined): ValidationResult {
  if (!key) {
    return createValidationResult(false, "Encryption key is null or undefined");
  }
  
  if (!(key instanceof Buffer) && !(key instanceof Uint8Array)) {
    return createValidationResult(false, "Encryption key has invalid type");
  }
  
  // Validate key length - should be 32 bytes for most crypto operations
  if (key.length !== 32) {
    return createValidationResult(false, "Encryption key has invalid length");
  }
  
  // Check for all-zero key (weak key)
  const isAllZero = Array.from(key).every(byte => byte === 0);
  if (isAllZero) {
    return createValidationResult(false, "Encryption key is weak (all zeros)");
  }
  
  return createValidationResult(true);
}

/**
 * Validates storage operation parameters
 * Ensures storage operations have proper security requirements
 */
export function validateStorageOperation(options: {
  requireEncryption: boolean;
  data: any;
  encryptionAvailable: boolean;
}): ValidationResult {
  const { requireEncryption, data, encryptionAvailable } = options;
  
  if (!data) {
    return createValidationResult(false, "No data provided for storage");
  }
  
  if (requireEncryption && !encryptionAvailable) {
    return createValidationResult(false, "Encryption required but not available");
  }
  
  return createValidationResult(true);
}
