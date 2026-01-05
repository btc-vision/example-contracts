/**
 * OPNet BTC Name Resolver - Event Definitions
 *
 * All events emitted by the BTC Name Resolver contract.
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
// Domain Events
// =============================================================================

/**
 * Emitted when a new domain is registered.
 * @param domainHash - SHA256 hash of the domain name
 * @param owner - Address of the domain owner
 * @param timestamp - Block number when registered
 */
@final
export class DomainRegisteredEvent extends NetEvent {
    constructor(domainHash: u256, owner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U64_BYTE_LENGTH,
        );
        data.writeU256(domainHash);
        data.writeAddress(owner);
        data.writeU64(timestamp);

        super('DomainRegistered', data);
    }
}

/**
 * Emitted when a domain transfer is initiated.
 * @param domainHash - SHA256 hash of the domain name
 * @param currentOwner - Address of the current owner
 * @param newOwner - Address of the pending new owner
 * @param timestamp - Block number when initiated
 */
@final
export class DomainTransferInitiatedEvent extends NetEvent {
    constructor(domainHash: u256, currentOwner: Address, newOwner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH * 2 + U64_BYTE_LENGTH,
        );
        data.writeU256(domainHash);
        data.writeAddress(currentOwner);
        data.writeAddress(newOwner);
        data.writeU64(timestamp);

        super('DomainTransferInitiated', data);
    }
}

/**
 * Emitted when a domain transfer is completed.
 * @param domainHash - SHA256 hash of the domain name
 * @param previousOwner - Address of the previous owner
 * @param newOwner - Address of the new owner
 * @param timestamp - Block number when completed
 */
@final
export class DomainTransferCompletedEvent extends NetEvent {
    constructor(domainHash: u256, previousOwner: Address, newOwner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH * 2 + U64_BYTE_LENGTH,
        );
        data.writeU256(domainHash);
        data.writeAddress(previousOwner);
        data.writeAddress(newOwner);
        data.writeU64(timestamp);

        super('DomainTransferCompleted', data);
    }
}

/**
 * Emitted when a domain transfer is cancelled.
 * @param domainHash - SHA256 hash of the domain name
 * @param owner - Address of the owner who cancelled
 * @param timestamp - Block number when cancelled
 */
@final
export class DomainTransferCancelledEvent extends NetEvent {
    constructor(domainHash: u256, owner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U64_BYTE_LENGTH,
        );
        data.writeU256(domainHash);
        data.writeAddress(owner);
        data.writeU64(timestamp);

        super('DomainTransferCancelled', data);
    }
}

// =============================================================================
// Subdomain Events
// =============================================================================

/**
 * Emitted when a subdomain is created.
 * @param parentDomainHash - SHA256 hash of the parent domain
 * @param subdomainHash - SHA256 hash of the full subdomain name
 * @param owner - Address of the subdomain owner
 * @param timestamp - Block number when created
 */
@final
export class SubdomainCreatedEvent extends NetEvent {
    constructor(parentDomainHash: u256, subdomainHash: u256, owner: Address, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH * 2 + ADDRESS_BYTE_LENGTH + U64_BYTE_LENGTH,
        );
        data.writeU256(parentDomainHash);
        data.writeU256(subdomainHash);
        data.writeAddress(owner);
        data.writeU64(timestamp);

        super('SubdomainCreated', data);
    }
}

/**
 * Emitted when a subdomain is deleted.
 * @param parentDomainHash - SHA256 hash of the parent domain
 * @param subdomainHash - SHA256 hash of the full subdomain name
 * @param timestamp - Block number when deleted
 */
@final
export class SubdomainDeletedEvent extends NetEvent {
    constructor(parentDomainHash: u256, subdomainHash: u256, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH * 2 + U64_BYTE_LENGTH);
        data.writeU256(parentDomainHash);
        data.writeU256(subdomainHash);
        data.writeU64(timestamp);

        super('SubdomainDeleted', data);
    }
}

// =============================================================================
// Contenthash Events
// =============================================================================

/**
 * Emitted when contenthash is set or updated.
 * @param nameHash - SHA256 hash of the domain/subdomain name
 * @param contenthashType - Type of contenthash (1=CIDv0, 2=CIDv1, 3=IPNS, 4=SHA256)
 * @param timestamp - Block number when changed
 */
@final
export class ContenthashChangedEvent extends NetEvent {
    constructor(nameHash: u256, contenthashType: u8, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + U8_BYTE_LENGTH + U64_BYTE_LENGTH,
        );
        data.writeU256(nameHash);
        data.writeU8(contenthashType);
        data.writeU64(timestamp);

        super('ContenthashChanged', data);
    }
}

/**
 * Emitted when contenthash is cleared.
 * @param nameHash - SHA256 hash of the domain/subdomain name
 * @param timestamp - Block number when cleared
 */
@final
export class ContenthashClearedEvent extends NetEvent {
    constructor(nameHash: u256, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH + U64_BYTE_LENGTH);
        data.writeU256(nameHash);
        data.writeU64(timestamp);

        super('ContenthashCleared', data);
    }
}

// =============================================================================
// TTL Events
// =============================================================================

/**
 * Emitted when TTL is changed for a name.
 * @param nameHash - SHA256 hash of the domain/subdomain name
 * @param oldTTL - Previous TTL value in seconds
 * @param newTTL - New TTL value in seconds
 * @param timestamp - Block number when changed
 */
@final
export class TTLChangedEvent extends NetEvent {
    constructor(nameHash: u256, oldTTL: u64, newTTL: u64, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH + U64_BYTE_LENGTH * 3);
        data.writeU256(nameHash);
        data.writeU64(oldTTL);
        data.writeU64(newTTL);
        data.writeU64(timestamp);

        super('TTLChanged', data);
    }
}

// =============================================================================
// Admin Events
// =============================================================================

/**
 * Emitted when domain pricing is changed.
 * @param oldPrice - Previous price in satoshis
 * @param newPrice - New price in satoshis
 * @param timestamp - Block number when changed
 */
@final
export class DomainPriceChangedEvent extends NetEvent {
    constructor(oldPrice: u64, newPrice: u64, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(U64_BYTE_LENGTH * 3);
        data.writeU64(oldPrice);
        data.writeU64(newPrice);
        data.writeU64(timestamp);

        super('DomainPriceChanged', data);
    }
}

/**
 * Emitted when treasury address is changed.
 * @param previousAddressHash - Hash of the previous treasury address
 * @param newAddressHash - Hash of the new treasury address
 * @param timestamp - Block number when changed
 */
@final
export class TreasuryChangedEvent extends NetEvent {
    constructor(previousAddressHash: u256, newAddressHash: u256, timestamp: u64) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH * 2 + U64_BYTE_LENGTH);
        data.writeU256(previousAddressHash);
        data.writeU256(newAddressHash);
        data.writeU64(timestamp);

        super('TreasuryChanged', data);
    }
}
