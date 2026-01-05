/**
 * OPNet Package Registry - Constants
 *
 * This file contains all constants used by the Package Registry contract.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// =============================================================================
// Plugin Types
// =============================================================================

/** Standalone plugin that runs independently */
export const PLUGIN_STANDALONE: u8 = 1;

/** Library plugin that provides shared functionality */
export const PLUGIN_LIBRARY: u8 = 2;

// =============================================================================
// String Length Limits
// =============================================================================

/** Maximum length of a scope name (without @) */
export const MAX_SCOPE_LENGTH: u32 = 32;

/** Maximum length of an unscoped package name */
export const MAX_NAME_LENGTH: u32 = 64;

/** Maximum length of a version string (semver) */
export const MAX_VERSION_LENGTH: u32 = 32;

/** Maximum length of an IPFS CID string */
export const MAX_CID_LENGTH: u32 = 128;

/** Maximum length of an OPNet version range string */
export const MAX_OPNET_RANGE_LENGTH: u32 = 64;

/** Maximum length of a deprecation reason string */
export const MAX_REASON_LENGTH: u32 = 256;

// =============================================================================
// Block Constants
// =============================================================================

/** 72-hour mutability window in blocks (~432 blocks, assuming 10 min/block) */
export const MUTABILITY_WINDOW_BLOCKS: u64 = 432;

// =============================================================================
// Pricing Defaults (in satoshis)
// =============================================================================

/** Default price to register an unscoped package: 10,000 sats */
export const DEFAULT_PACKAGE_PRICE_SATS: u64 = 10_000;

/** Default price to register a scope: ~$50 worth of sats (adjustable by owner) */
export const DEFAULT_SCOPE_PRICE_SATS: u64 = 50_000;

// =============================================================================
// Reserved Scopes
// =============================================================================

/** The @opnet scope is reserved for the contract deployer */
export const RESERVED_SCOPE: string = 'opnet';
