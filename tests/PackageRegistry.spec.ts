import {
    DEFAULT_PACKAGE_PRICE_SATS,
    DEFAULT_SCOPE_PRICE_SATS,
    MAX_CID_LENGTH,
    MAX_NAME_LENGTH,
    MAX_OPNET_RANGE_LENGTH,
    MAX_REASON_LENGTH,
    MAX_SCOPE_LENGTH,
    MAX_VERSION_LENGTH,
    MUTABILITY_WINDOW_BLOCKS,
    PLUGIN_LIBRARY,
    PLUGIN_STANDALONE,
    RESERVED_SCOPE,
} from '../src/registry/constants';

import {
    MLDSA44_SIGNATURE_LEN,
    MLDSA65_SIGNATURE_LEN,
    MLDSA87_SIGNATURE_LEN,
} from '@btc-vision/btc-runtime/runtime/env/consensus/MLDSAMetadata';

// MLDSA security levels
const MLDSA44: u8 = 1;
const MLDSA65: u8 = 2;
const MLDSA87: u8 = 3;

/**
 * PackageRegistry Unit Tests
 *
 * Tests for the OPNet Package Registry smart contract.
 * Covers validation functions and helper utilities.
 * Note: Tests that require Blockchain imports (sha256, etc.) are excluded
 * as they require the full runtime environment.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// ============================================================================
// Constants Tests
// ============================================================================

describe('Constants', () => {
    describe('MLDSA Levels', () => {
        it('should have correct MLDSA level values', () => {
            expect(MLDSA44).toBe(1);
            expect(MLDSA65).toBe(2);
            expect(MLDSA87).toBe(3);
        });

        it('should have correct MLDSA signature lengths', () => {
            expect(MLDSA44_SIGNATURE_LEN).toBe(2420);
            expect(MLDSA65_SIGNATURE_LEN).toBe(3309);
            expect(MLDSA87_SIGNATURE_LEN).toBe(4627);
        });
    });

    describe('Plugin Types', () => {
        it('should have correct plugin type values', () => {
            expect(PLUGIN_STANDALONE).toBe(1);
            expect(PLUGIN_LIBRARY).toBe(2);
        });
    });

    describe('Length Limits', () => {
        it('should have correct length limits', () => {
            expect(MAX_SCOPE_LENGTH).toBe(32);
            expect(MAX_NAME_LENGTH).toBe(64);
            expect(MAX_VERSION_LENGTH).toBe(32);
            expect(MAX_CID_LENGTH).toBe(128);
            expect(MAX_OPNET_RANGE_LENGTH).toBe(64);
            expect(MAX_REASON_LENGTH).toBe(256);
        });
    });

    describe('Block Constants', () => {
        it('should have correct mutability window in blocks (~72 hours)', () => {
            expect(MUTABILITY_WINDOW_BLOCKS).toBe(432); // ~432 blocks at 10 min/block
        });
    });

    describe('Pricing', () => {
        it('should have correct default pricing', () => {
            expect(DEFAULT_PACKAGE_PRICE_SATS).toBe(10000);
            expect(DEFAULT_SCOPE_PRICE_SATS).toBe(50000);
        });
    });

    describe('Reserved Scope', () => {
        it('should have opnet as reserved scope', () => {
            expect(RESERVED_SCOPE).toBe('opnet');
        });
    });
});

// ============================================================================
// Validation Logic Tests (Reimplemented for testing)
// ============================================================================

/**
 * Validate scope name format (reimplemented for testing)
 */
function validateScopeName(scope: string): bool {
    const len = scope.length;
    if (len < 1 || len > <i32>MAX_SCOPE_LENGTH) return false;

    const first = scope.charCodeAt(0);
    if (first < 97 || first > 122) return false; // Must start with lowercase letter

    for (let i = 1; i < len; i++) {
        const c = scope.charCodeAt(i);
        const isLower = c >= 97 && c <= 122;
        const isDigit = c >= 48 && c <= 57;
        const isHyphen = c == 45;

        if (!isLower && !isDigit && !isHyphen) return false;
    }
    return true;
}

/**
 * Validate unscoped package name format
 */
function validateUnscopedName(name: string): bool {
    const len = name.length;
    if (len < 1 || len > <i32>MAX_NAME_LENGTH) return false;

    const first = name.charCodeAt(0);
    if (first < 97 || first > 122) return false;

    for (let i = 1; i < len; i++) {
        const c = name.charCodeAt(i);
        const isLower = c >= 97 && c <= 122;
        const isDigit = c >= 48 && c <= 57;
        const isHyphen = c == 45;

        if (!isLower && !isDigit && !isHyphen) return false;
    }
    return true;
}

/**
 * Check if package name is scoped
 */
function isScoped(packageName: string): bool {
    return packageName.length > 0 && packageName.charCodeAt(0) == 64;
}

/**
 * Validate IPFS CID format
 */
function validateIpfsCid(cid: string): bool {
    const len = cid.length;
    if (len < 46 || len > <i32>MAX_CID_LENGTH) return false;

    // CIDv0: starts with "Qm"
    const isV0 = cid.charCodeAt(0) == 81 && cid.charCodeAt(1) == 109;

    // CIDv1: starts with "baf" (covers bafy, bafk, bafz, etc.)
    const isV1 = cid.charCodeAt(0) == 98 && cid.charCodeAt(1) == 97 && cid.charCodeAt(2) == 102;

    return isV0 || isV1;
}

/**
 * Validate version string format (semver: x.y.z)
 */
function validateVersionString(version: string): bool {
    const len = version.length;
    if (len < 5 || len > <i32>MAX_VERSION_LENGTH) return false;

    const first = version.charCodeAt(0);
    if (first < 48 || first > 57) return false;

    let dotCount: i32 = 0;
    let lastWasDot = false;

    for (let i: i32 = 0; i < len; i++) {
        const c = version.charCodeAt(i);
        const isDot = c == 46;
        const isDigit = c >= 48 && c <= 57;
        const isHyphen = c == 45;

        if (isHyphen) {
            if (dotCount < 2) return false;
            break;
        }

        if (isDot) {
            if (lastWasDot) return false;
            dotCount++;
            lastWasDot = true;
        } else if (isDigit) {
            lastWasDot = false;
        } else {
            return false;
        }
    }

    return dotCount >= 2;
}

/**
 * Validate OPNet version range string format
 */
function validateOpnetVersionRange(range: string): bool {
    const len = range.length;
    if (len == 0 || len > <i32>MAX_OPNET_RANGE_LENGTH) return false;

    let hasDigit = false;
    for (let i: i32 = 0; i < len; i++) {
        const c = range.charCodeAt(i);
        if (c >= 48 && c <= 57) {
            hasDigit = true;
            break;
        }
    }
    if (!hasDigit) return false;

    for (let i: i32 = 0; i < len; i++) {
        const c = range.charCodeAt(i);
        const isDigit = c >= 48 && c <= 57;
        const isDot = c == 46;
        const isSpace = c == 32;
        const isCompare = c == 60 || c == 62 || c == 61 || c == 94 || c == 126;
        const isLogical = c == 124 || c == 38;
        const isWildcard = c == 120 || c == 42;
        const isHyphen = c == 45;

        if (
            !isDigit &&
            !isDot &&
            !isSpace &&
            !isCompare &&
            !isLogical &&
            !isWildcard &&
            !isHyphen
        ) {
            return false;
        }
    }
    return true;
}

/**
 * Validate treasury address format (bc1p or bc1q)
 */
function validateTreasuryAddress(address: string): bool {
    const len = address.length;
    if (len < 42 || len > 62) return false;

    if (address.charCodeAt(0) != 98 || address.charCodeAt(1) != 99 || address.charCodeAt(2) != 49) {
        return false;
    }

    const fourth = address.charCodeAt(3);
    if (fourth != 112 && fourth != 113) return false;

    for (let i: i32 = 4; i < len; i++) {
        const c = address.charCodeAt(i);
        const isDigit = c >= 48 && c <= 57 && c != 49;
        const isLower = c >= 97 && c <= 122 && c != 98 && c != 105 && c != 111;

        if (!isDigit && !isLower) return false;
    }
    return true;
}

/**
 * Validate signature length matches MLDSA level
 */
function validateSignatureLength(sigLen: u32, mldsaLevel: u8): bool {
    if (mldsaLevel == 1) return sigLen == MLDSA44_SIGNATURE_LEN;
    if (mldsaLevel == 2) return sigLen == MLDSA65_SIGNATURE_LEN;
    if (mldsaLevel == 3) return sigLen == MLDSA87_SIGNATURE_LEN;
    return false;
}

// ============================================================================
// Scope Name Validation Tests
// ============================================================================

describe('Scope Name Validation', () => {
    describe('Valid scope names', () => {
        it('should accept simple lowercase names', () => {
            expect(validateScopeName('opnet')).toBe(true);
            expect(validateScopeName('myorg')).toBe(true);
            expect(validateScopeName('abc')).toBe(true);
        });

        it('should accept names with digits', () => {
            expect(validateScopeName('org123')).toBe(true);
            expect(validateScopeName('my2org')).toBe(true);
        });

        it('should accept names with hyphens', () => {
            expect(validateScopeName('my-org')).toBe(true);
            expect(validateScopeName('my-cool-org')).toBe(true);
        });

        it('should accept single character names', () => {
            expect(validateScopeName('a')).toBe(true);
            expect(validateScopeName('z')).toBe(true);
        });

        it('should accept maximum length names (32 chars)', () => {
            expect(validateScopeName('abcdefghijklmnopqrstuvwxyz123456')).toBe(true);
        });
    });

    describe('Invalid scope names', () => {
        it('should reject empty names', () => {
            expect(validateScopeName('')).toBe(false);
        });

        it('should reject names starting with digit', () => {
            expect(validateScopeName('1org')).toBe(false);
            expect(validateScopeName('123abc')).toBe(false);
        });

        it('should reject names starting with hyphen', () => {
            expect(validateScopeName('-myorg')).toBe(false);
        });

        it('should reject uppercase letters', () => {
            expect(validateScopeName('MyOrg')).toBe(false);
            expect(validateScopeName('OPNET')).toBe(false);
        });

        it('should reject special characters', () => {
            expect(validateScopeName('my_org')).toBe(false);
            expect(validateScopeName('my.org')).toBe(false);
            expect(validateScopeName('my@org')).toBe(false);
        });

        it('should reject names exceeding 32 chars', () => {
            expect(validateScopeName('abcdefghijklmnopqrstuvwxyz1234567')).toBe(false);
        });
    });
});

// ============================================================================
// Package Name Validation Tests
// ============================================================================

describe('Package Name Validation', () => {
    describe('Unscoped package names', () => {
        it('should accept valid unscoped names', () => {
            expect(validateUnscopedName('my-package')).toBe(true);
            expect(validateUnscopedName('cli')).toBe(true);
            expect(validateUnscopedName('runtime123')).toBe(true);
        });

        it('should reject invalid unscoped names', () => {
            expect(validateUnscopedName('')).toBe(false);
            expect(validateUnscopedName('1package')).toBe(false);
            expect(validateUnscopedName('My-Package')).toBe(false);
        });
    });

    describe('Scoped package detection', () => {
        it('should detect scoped packages', () => {
            expect(isScoped('@opnet/cli')).toBe(true);
            expect(isScoped('@myorg/package')).toBe(true);
        });

        it('should detect unscoped packages', () => {
            expect(isScoped('my-package')).toBe(false);
            expect(isScoped('cli')).toBe(false);
        });

        it('should handle empty string', () => {
            expect(isScoped('')).toBe(false);
        });
    });
});

// ============================================================================
// Version String Validation Tests
// ============================================================================

describe('Version String Validation', () => {
    describe('Valid versions', () => {
        it('should accept standard semver versions', () => {
            expect(validateVersionString('1.0.0')).toBe(true);
            expect(validateVersionString('0.0.1')).toBe(true);
            expect(validateVersionString('10.20.30')).toBe(true);
        });

        it('should accept pre-release versions', () => {
            expect(validateVersionString('1.0.0-alpha')).toBe(true);
            expect(validateVersionString('1.0.0-beta.1')).toBe(true);
            expect(validateVersionString('2.0.0-rc.1')).toBe(true);
        });

        it('should accept versions with larger numbers', () => {
            expect(validateVersionString('100.200.300')).toBe(true);
        });
    });

    describe('Invalid versions', () => {
        it('should reject versions with only two parts', () => {
            expect(validateVersionString('1.0')).toBe(false);
        });

        it('should reject versions starting with letter', () => {
            expect(validateVersionString('v1.0.0')).toBe(false);
        });

        it('should reject versions with consecutive dots', () => {
            expect(validateVersionString('1..0.0')).toBe(false);
        });

        it('should reject versions with special characters', () => {
            expect(validateVersionString('1.0.0_beta')).toBe(false);
        });

        it('should reject too short versions', () => {
            expect(validateVersionString('1.0')).toBe(false);
        });
    });
});

// ============================================================================
// IPFS CID Validation Tests
// ============================================================================

describe('IPFS CID Validation', () => {
    describe('Valid CIDs', () => {
        it('should accept CIDv0 (Qm...)', () => {
            expect(validateIpfsCid('QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG')).toBe(true);
            expect(validateIpfsCid('QmZtmD2qt6fJot32nabSP3CUjicnypEBz7bHVDhPQt9aAy')).toBe(true);
        });

        it('should accept CIDv1 (bafy...)', () => {
            expect(
                validateIpfsCid('bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'),
            ).toBe(true);
        });

        it('should accept CIDv1 with other codecs (bafk...)', () => {
            // bafk is CIDv1 with raw codec - 59 chars is valid
            expect(
                validateIpfsCid('bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi'),
            ).toBe(true);
        });
    });

    describe('Invalid CIDs', () => {
        it('should reject empty string', () => {
            expect(validateIpfsCid('')).toBe(false);
        });

        it('should reject CIDs too short (< 46 chars)', () => {
            expect(validateIpfsCid('QmShort')).toBe(false);
            expect(validateIpfsCid('bafyshort')).toBe(false);
        });

        it('should reject CIDs not starting with Qm or baf', () => {
            // zdj is base58btc CIDv1 - not supported
            expect(validateIpfsCid('zdj7Wn9FQAURCP6MbwcWuzi7u65kAsXCdjNTkhbJcoaXBusq9')).toBe(
                false,
            );
        });

        it('should reject invalid prefixes with valid length', () => {
            // 46 chars but wrong prefix
            expect(validateIpfsCid('abcdefghijklmnopqrstuvwxyz12345678901234567890')).toBe(false);
        });
    });
});

// ============================================================================
// OPNet Version Range Validation Tests
// ============================================================================

describe('OPNet Version Range Validation', () => {
    describe('Valid ranges', () => {
        it('should accept simple version ranges', () => {
            expect(validateOpnetVersionRange('>=1.0.0')).toBe(true);
            expect(validateOpnetVersionRange('<2.0.0')).toBe(true);
            expect(validateOpnetVersionRange('>=1.0.0 <2.0.0')).toBe(true);
        });

        it('should accept caret and tilde ranges', () => {
            expect(validateOpnetVersionRange('^1.0.0')).toBe(true);
            expect(validateOpnetVersionRange('~1.0.0')).toBe(true);
        });

        it('should accept wildcard ranges', () => {
            expect(validateOpnetVersionRange('1.x')).toBe(true);
            expect(validateOpnetVersionRange('1.*')).toBe(true);
        });

        it('should accept hyphen ranges', () => {
            expect(validateOpnetVersionRange('1.0.0 - 2.0.0')).toBe(true);
        });
    });

    describe('Invalid ranges', () => {
        it('should reject empty range', () => {
            expect(validateOpnetVersionRange('')).toBe(false);
        });

        it('should reject range without digits', () => {
            expect(validateOpnetVersionRange('>=')).toBe(false);
            expect(validateOpnetVersionRange('abc')).toBe(false);
        });

        it('should reject ranges with invalid characters', () => {
            expect(validateOpnetVersionRange('>=1.0.0!')).toBe(false);
            expect(validateOpnetVersionRange('1.0.0@beta')).toBe(false);
        });
    });
});

// ============================================================================
// Treasury Address Validation Tests
// ============================================================================

describe('Treasury Address Validation', () => {
    describe('Valid addresses', () => {
        it('should accept bc1p taproot addresses', () => {
            // Valid taproot address format (62 chars)
            expect(
                validateTreasuryAddress(
                    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
                ),
            ).toBe(true);
        });

        it('should accept bc1q segwit addresses', () => {
            // Valid segwit address format (42-62 chars)
            expect(validateTreasuryAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).toBe(
                true,
            );
        });
    });

    describe('Invalid addresses', () => {
        it('should reject addresses too short', () => {
            expect(validateTreasuryAddress('bc1qshort')).toBe(false);
        });

        it('should reject addresses too long', () => {
            const longAddr =
                'bc1p' + 'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq';
            expect(validateTreasuryAddress(longAddr)).toBe(false);
        });

        it('should reject non-bc1 addresses', () => {
            expect(validateTreasuryAddress('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2aaaaaaaaaaa')).toBe(
                false,
            );
            expect(validateTreasuryAddress('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLyaaa')).toBe(false);
        });

        it('should reject bc1 without p or q', () => {
            expect(
                validateTreasuryAddress('bc1r0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq'),
            ).toBe(false);
        });

        it('should reject invalid bech32 characters', () => {
            // Contains 'b' after bc1p which is invalid in bech32
            expect(
                validateTreasuryAddress(
                    'bc1pbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                ),
            ).toBe(false);
        });
    });
});

// ============================================================================
// Signature Length Validation Tests
// ============================================================================

describe('Signature Length Validation', () => {
    describe('MLDSA-44 signatures', () => {
        it('should accept correct length (2420 bytes)', () => {
            expect(validateSignatureLength(2420, 1)).toBe(true);
        });

        it('should reject incorrect lengths', () => {
            expect(validateSignatureLength(2419, 1)).toBe(false);
            expect(validateSignatureLength(2421, 1)).toBe(false);
            expect(validateSignatureLength(0, 1)).toBe(false);
        });
    });

    describe('MLDSA-65 signatures', () => {
        it('should accept correct length (3309 bytes)', () => {
            expect(validateSignatureLength(3309, 2)).toBe(true);
        });

        it('should reject incorrect lengths', () => {
            expect(validateSignatureLength(3308, 2)).toBe(false);
            expect(validateSignatureLength(3310, 2)).toBe(false);
        });
    });

    describe('MLDSA-87 signatures', () => {
        it('should accept correct length (4627 bytes)', () => {
            expect(validateSignatureLength(4627, 3)).toBe(true);
        });

        it('should reject incorrect lengths', () => {
            expect(validateSignatureLength(4626, 3)).toBe(false);
            expect(validateSignatureLength(4628, 3)).toBe(false);
        });
    });

    describe('Invalid MLDSA levels', () => {
        it('should reject level 0', () => {
            expect(validateSignatureLength(2420, 0)).toBe(false);
        });

        it('should reject level 4+', () => {
            expect(validateSignatureLength(2420, 4)).toBe(false);
            expect(validateSignatureLength(2420, 255)).toBe(false);
        });
    });
});

// ============================================================================
// Edge Cases Tests
// ============================================================================

describe('Edge Cases', () => {
    describe('Boundary values', () => {
        it('should handle minimum valid scope name', () => {
            expect(validateScopeName('a')).toBe(true);
        });

        it('should handle maximum valid scope name', () => {
            // 32 characters
            const maxScope = 'abcdefghijklmnopqrstuvwxyz123456';
            expect(maxScope.length).toBe(32);
            expect(validateScopeName(maxScope)).toBe(true);
        });

        it('should handle minimum valid version', () => {
            expect(validateVersionString('0.0.0')).toBe(true);
        });

        it('should handle minimum valid CID (46 chars)', () => {
            // CIDv0 is exactly 46 characters
            expect(validateIpfsCid('QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG')).toBe(true);
        });
    });

    describe('Unicode and special handling', () => {
        it('should reject unicode characters in scope names', () => {
            // These contain non-ASCII characters
            expect(validateScopeName('org\u00e9')).toBe(false);
        });

        it('should reject unicode in package names', () => {
            expect(validateUnscopedName('package\u00e9')).toBe(false);
        });
    });
});

// ============================================================================
// Integration-Style Tests
// ============================================================================

describe('Package Registry Flow Validation', () => {
    describe('Scope registration flow', () => {
        it('should validate a complete scope registration', () => {
            const scopeName = 'myorg';

            // Validate scope name
            expect(validateScopeName(scopeName)).toBe(true);
        });
    });

    describe('Package registration flow', () => {
        it('should validate scoped package registration', () => {
            const packageName = '@myorg/cli';

            // Check if scoped
            expect(isScoped(packageName)).toBe(true);

            // Extract and validate scope
            const slashIdx = packageName.indexOf('/');
            const scope = packageName.substring(1, slashIdx);
            const pkgName = packageName.substring(slashIdx + 1);

            expect(validateScopeName(scope)).toBe(true);
            expect(validateUnscopedName(pkgName)).toBe(true);
        });

        it('should validate unscoped package registration', () => {
            const packageName = 'standalone-plugin';

            expect(isScoped(packageName)).toBe(false);
            expect(validateUnscopedName(packageName)).toBe(true);
        });
    });

    describe('Version publishing flow', () => {
        it('should validate all version publishing inputs', () => {
            const version = '1.0.0';
            const ipfsCid = 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG';
            const mldsaLevel: u8 = 2;
            const opnetRange = '>=1.0.0 <2.0.0';
            const pluginType: u8 = 1;

            expect(validateVersionString(version)).toBe(true);
            expect(validateIpfsCid(ipfsCid)).toBe(true);
            expect(mldsaLevel >= 1 && mldsaLevel <= 3).toBe(true);
            expect(validateOpnetVersionRange(opnetRange)).toBe(true);
            expect(pluginType >= 1 && pluginType <= 2).toBe(true);
            expect(validateSignatureLength(MLDSA65_SIGNATURE_LEN, mldsaLevel)).toBe(true);
        });
    });

    describe('Treasury address setup', () => {
        it('should validate treasury address configuration', () => {
            const taprootAddr = 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0';
            const segwitAddr = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';

            expect(validateTreasuryAddress(taprootAddr)).toBe(true);
            expect(validateTreasuryAddress(segwitAddr)).toBe(true);
        });
    });
});
