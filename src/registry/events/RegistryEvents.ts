/**
 * OPNet Package Registry - Event Definitions
 *
 * All events emitted by the Package Registry contract.
 * Events are used for indexing and tracking state changes.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    ADDRESS_BYTE_LENGTH,
    BytesWriter,
    NetEvent,
    U256_BYTE_LENGTH,
    U64_BYTE_LENGTH,
    U8_BYTE_LENGTH,
} from '@btc-vision/btc-runtime/runtime';

// =============================================================================
// Scope Events
// =============================================================================

/**
 * Emitted when a new scope is registered.
 * @param scopeHash - SHA256 hash of the scope name (without @)
 * @param owner - Address of the scope owner
 * @param timestamp - Block timestamp when registered
 */
@final
export class ScopeRegisteredEvent extends NetEvent {
    constructor(scopeHash: u256, owner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U64_BYTE_LENGTH,
        );
        data.writeU256(scopeHash);
        data.writeAddress(owner);
        data.writeU64(timestamp);

        super('ScopeRegistered', data);
    }
}

/**
 * Emitted when a scope ownership transfer is initiated.
 * @param scopeHash - SHA256 hash of the scope name
 * @param currentOwner - Address of the current owner
 * @param newOwner - Address of the pending new owner
 * @param timestamp - Block timestamp when initiated
 */
@final
export class ScopeTransferInitiatedEvent extends NetEvent {
    constructor(scopeHash: u256, currentOwner: Address, newOwner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH * 2 + U64_BYTE_LENGTH,
        );
        data.writeU256(scopeHash);
        data.writeAddress(currentOwner);
        data.writeAddress(newOwner);
        data.writeU64(timestamp);

        super('ScopeTransferInitiated', data);
    }
}

/**
 * Emitted when a scope ownership transfer is completed.
 * @param scopeHash - SHA256 hash of the scope name
 * @param previousOwner - Address of the previous owner
 * @param newOwner - Address of the new owner
 * @param timestamp - Block timestamp when completed
 */
@final
export class ScopeTransferCompletedEvent extends NetEvent {
    constructor(scopeHash: u256, previousOwner: Address, newOwner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH * 2 + U64_BYTE_LENGTH,
        );
        data.writeU256(scopeHash);
        data.writeAddress(previousOwner);
        data.writeAddress(newOwner);
        data.writeU64(timestamp);

        super('ScopeTransferCompleted', data);
    }
}

/**
 * Emitted when a scope ownership transfer is cancelled.
 * @param scopeHash - SHA256 hash of the scope name
 * @param owner - Address of the owner who cancelled
 * @param timestamp - Block timestamp when cancelled
 */
@final
export class ScopeTransferCancelledEvent extends NetEvent {
    constructor(scopeHash: u256, owner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U64_BYTE_LENGTH,
        );
        data.writeU256(scopeHash);
        data.writeAddress(owner);
        data.writeU64(timestamp);

        super('ScopeTransferCancelled', data);
    }
}

// =============================================================================
// Package Events
// =============================================================================

/**
 * Emitted when a new package is registered.
 * @param packageHash - SHA256 hash of the full package name
 * @param owner - Address of the package owner
 * @param timestamp - Block timestamp when registered
 */
@final
export class PackageRegisteredEvent extends NetEvent {
    constructor(packageHash: u256, owner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U64_BYTE_LENGTH,
        );
        data.writeU256(packageHash);
        data.writeAddress(owner);
        data.writeU64(timestamp);

        super('PackageRegistered', data);
    }
}

/**
 * Emitted when a package ownership transfer is initiated.
 * @param packageHash - SHA256 hash of the package name
 * @param currentOwner - Address of the current owner
 * @param newOwner - Address of the pending new owner
 * @param timestamp - Block timestamp when initiated
 */
@final
export class PackageTransferInitiatedEvent extends NetEvent {
    constructor(packageHash: u256, currentOwner: Address, newOwner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH * 2 + U64_BYTE_LENGTH,
        );
        data.writeU256(packageHash);
        data.writeAddress(currentOwner);
        data.writeAddress(newOwner);
        data.writeU64(timestamp);

        super('PackageTransferInitiated', data);
    }
}

/**
 * Emitted when a package ownership transfer is completed.
 * @param packageHash - SHA256 hash of the package name
 * @param previousOwner - Address of the previous owner
 * @param newOwner - Address of the new owner
 * @param timestamp - Block timestamp when completed
 */
@final
export class PackageTransferCompletedEvent extends NetEvent {
    constructor(packageHash: u256, previousOwner: Address, newOwner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH * 2 + U64_BYTE_LENGTH,
        );
        data.writeU256(packageHash);
        data.writeAddress(previousOwner);
        data.writeAddress(newOwner);
        data.writeU64(timestamp);

        super('PackageTransferCompleted', data);
    }
}

/**
 * Emitted when a package ownership transfer is cancelled.
 * @param packageHash - SHA256 hash of the package name
 * @param owner - Address of the owner who cancelled
 * @param timestamp - Block timestamp when cancelled
 */
@final
export class PackageTransferCancelledEvent extends NetEvent {
    constructor(packageHash: u256, owner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U64_BYTE_LENGTH,
        );
        data.writeU256(packageHash);
        data.writeAddress(owner);
        data.writeU64(timestamp);

        super('PackageTransferCancelled', data);
    }
}

// =============================================================================
// Version Events
// =============================================================================

/**
 * Emitted when a new version is published.
 * @param packageHash - SHA256 hash of the package name
 * @param versionHash - SHA256 hash of the version string
 * @param publisher - Address of the publisher
 * @param checksum - SHA256 checksum of the binary
 * @param timestamp - Block timestamp when published
 * @param mldsaLevel - MLDSA security level (1, 2, or 3)
 * @param pluginType - Plugin type (1=standalone, 2=library)
 */
@final
export class VersionPublishedEvent extends NetEvent {
    constructor(
        packageHash: u256,
        versionHash: u256,
        publisher: Address,
        checksum: u256,
        timestamp: u64,
        mldsaLevel: u8,
        pluginType: u8,
    ) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH * 3 + ADDRESS_BYTE_LENGTH + U64_BYTE_LENGTH + U8_BYTE_LENGTH * 2,
        );
        data.writeU256(packageHash);
        data.writeU256(versionHash);
        data.writeAddress(publisher);
        data.writeU256(checksum);
        data.writeU64(timestamp);
        data.writeU8(mldsaLevel);
        data.writeU8(pluginType);

        super('VersionPublished', data);
    }
}

/**
 * Emitted when a version is deprecated.
 * @param packageHash - SHA256 hash of the package name
 * @param versionHash - SHA256 hash of the version string
 * @param timestamp - Block timestamp when deprecated
 */
@final
export class VersionDeprecatedEvent extends NetEvent {
    constructor(packageHash: u256, versionHash: u256, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH * 2 + U64_BYTE_LENGTH);
        data.writeU256(packageHash);
        data.writeU256(versionHash);
        data.writeU64(timestamp);

        super('VersionDeprecated', data);
    }
}

/**
 * Emitted when a version deprecation is removed.
 * @param packageHash - SHA256 hash of the package name
 * @param versionHash - SHA256 hash of the version string
 * @param timestamp - Block timestamp when undeprecated
 */
@final
export class VersionUndeprecatedEvent extends NetEvent {
    constructor(packageHash: u256, versionHash: u256, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH * 2 + U64_BYTE_LENGTH);
        data.writeU256(packageHash);
        data.writeU256(versionHash);
        data.writeU64(timestamp);

        super('VersionUndeprecated', data);
    }
}

// =============================================================================
// Admin Events
// =============================================================================

/**
 * Emitted when the treasury address is changed.
 * @param previousAddress - Previous treasury address (as hash)
 * @param newAddress - New treasury address (as hash)
 * @param timestamp - Block timestamp when changed
 */
@final
export class TreasuryAddressChangedEvent extends NetEvent {
    constructor(previousAddressHash: u256, newAddressHash: u256, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH * 2 + U64_BYTE_LENGTH);
        data.writeU256(previousAddressHash);
        data.writeU256(newAddressHash);
        data.writeU64(timestamp);

        super('TreasuryAddressChanged', data);
    }
}

/**
 * Emitted when the scope price is changed.
 * @param oldPrice - Previous price in satoshis
 * @param newPrice - New price in satoshis
 * @param timestamp - Block timestamp when changed
 */
@final
export class ScopePriceChangedEvent extends NetEvent {
    constructor(oldPrice: u64, newPrice: u64, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(U64_BYTE_LENGTH * 3);
        data.writeU64(oldPrice);
        data.writeU64(newPrice);
        data.writeU64(timestamp);

        super('ScopePriceChanged', data);
    }
}

/**
 * Emitted when the package price is changed.
 * @param oldPrice - Previous price in satoshis
 * @param newPrice - New price in satoshis
 * @param timestamp - Block timestamp when changed
 */
@final
export class PackagePriceChangedEvent extends NetEvent {
    constructor(oldPrice: u64, newPrice: u64, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(U64_BYTE_LENGTH * 3);
        data.writeU64(oldPrice);
        data.writeU64(newPrice);
        data.writeU64(timestamp);

        super('PackagePriceChanged', data);
    }
}
