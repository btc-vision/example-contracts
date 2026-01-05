/**
 * OPNet BTC Name Resolver Smart Contract
 *
 * A decentralized domain name resolver for .btc domains. Manages:
 * - Domain ownership (mysite.btc)
 * - Subdomain support (sub.mysite.btc)
 * - Contenthash storage (CIDv0, CIDv1, IPNS, SHA-256)
 * - Two-step ownership transfers
 * - TTL (time-to-live) per domain
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    ADDRESS_BYTE_LENGTH,
    Blockchain,
    BytesWriter,
    Calldata,
    ExtendedAddress,
    OP_NET,
    Revert,
    SafeMath,
    StoredString,
    U256_BYTE_LENGTH,
    U64_BYTE_LENGTH,
} from '@btc-vision/btc-runtime/runtime';
import { StoredMapU256 } from '@btc-vision/btc-runtime/runtime/storage/maps/StoredMapU256';
import { AdvancedStoredString } from '@btc-vision/btc-runtime/runtime/storage/AdvancedStoredString';

import {
    ContenthashChangedEvent,
    ContenthashClearedEvent,
    DomainPriceChangedEvent,
    DomainRegisteredEvent,
    DomainTransferCancelledEvent,
    DomainTransferCompletedEvent,
    DomainTransferInitiatedEvent,
    SubdomainCreatedEvent,
    SubdomainDeletedEvent,
    TreasuryChangedEvent,
    TTLChangedEvent,
} from './events/ResolverEvents';

import {
    CONTENTHASH_TYPE_CIDv0,
    CONTENTHASH_TYPE_CIDv1,
    CONTENTHASH_TYPE_IPNS,
    CONTENTHASH_TYPE_SHA256,
    DEFAULT_DOMAIN_PRICE_SATS,
    DEFAULT_TTL,
    MAX_CONTENTHASH_LENGTH,
    MAX_DOMAIN_LENGTH,
    MAX_FULL_NAME_LENGTH,
    MAX_SUBDOMAIN_LENGTH,
    MAX_TTL,
    MIN_DOMAIN_LENGTH,
    MIN_TTL,
    PREMIUM_TIER_0_DOMAINS,
    PREMIUM_TIER_0_PRICE_SATS,
    PREMIUM_TIER_1_DOMAINS,
    PREMIUM_TIER_1_PRICE_SATS,
    PREMIUM_TIER_2_DOMAINS,
    PREMIUM_TIER_2_PRICE_SATS,
    PREMIUM_TIER_3_DOMAINS,
    PREMIUM_TIER_3_PRICE_SATS,
    PREMIUM_TIER_4_DOMAINS,
    PREMIUM_TIER_4_PRICE_SATS,
    PREMIUM_TIER_5_DOMAINS,
    PREMIUM_TIER_5_PRICE_SATS,
    PREMIUM_TIER_6_DOMAINS,
    RESERVED_DOMAIN,
} from './constants';

// =============================================================================
// Storage Pointer Allocation (Module Level - CRITICAL)
// =============================================================================

// Contract-level settings
const treasuryAddressPointer: u16 = Blockchain.nextPointer;
const domainPriceSatsPointer: u16 = Blockchain.nextPointer;

// Domain storage
const domainExistsPointer: u16 = Blockchain.nextPointer;
const domainOwnerPointer: u16 = Blockchain.nextPointer;
const domainCreatedPointer: u16 = Blockchain.nextPointer;
const domainTTLPointer: u16 = Blockchain.nextPointer;

// Domain transfer tracking
const domainPendingOwnerPointer: u16 = Blockchain.nextPointer;
const domainPendingTimestampPointer: u16 = Blockchain.nextPointer;

// Subdomain storage
const subdomainExistsPointer: u16 = Blockchain.nextPointer;
const subdomainOwnerPointer: u16 = Blockchain.nextPointer;
const subdomainParentPointer: u16 = Blockchain.nextPointer;
const subdomainTTLPointer: u16 = Blockchain.nextPointer;

// Contenthash storage
const contenthashTypePointer: u16 = Blockchain.nextPointer;
const contenthashDataPointer: u16 = Blockchain.nextPointer;
const contenthashStringPointer: u16 = Blockchain.nextPointer;

// =============================================================================
// Contract Implementation
// =============================================================================

@final
export class BtcNameResolver extends OP_NET {
    // -------------------------------------------------------------------------
    // Settings Storage
    // -------------------------------------------------------------------------
    private readonly treasuryAddress: StoredString;
    private readonly domainPriceSats: StoredMapU256;

    // -------------------------------------------------------------------------
    // Domain Storage Maps
    // -------------------------------------------------------------------------
    private readonly domainExists: StoredMapU256;
    private readonly domainOwner: StoredMapU256;
    private readonly domainCreated: StoredMapU256;
    private readonly domainTTL: StoredMapU256;
    private readonly domainPendingOwner: StoredMapU256;
    private readonly domainPendingTimestamp: StoredMapU256;

    // -------------------------------------------------------------------------
    // Subdomain Storage Maps
    // -------------------------------------------------------------------------
    private readonly subdomainExists: StoredMapU256;
    private readonly subdomainOwner: StoredMapU256;
    private readonly subdomainParent: StoredMapU256;
    private readonly subdomainTTL: StoredMapU256;

    // -------------------------------------------------------------------------
    // Contenthash Storage Maps
    // -------------------------------------------------------------------------
    private readonly contenthashType: StoredMapU256;
    private readonly contenthashData: StoredMapU256;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    public constructor() {
        super();

        // Initialize settings storage
        this.treasuryAddress = new StoredString(treasuryAddressPointer);
        this.domainPriceSats = new StoredMapU256(domainPriceSatsPointer);

        // Initialize domain storage
        this.domainExists = new StoredMapU256(domainExistsPointer);
        this.domainOwner = new StoredMapU256(domainOwnerPointer);
        this.domainCreated = new StoredMapU256(domainCreatedPointer);
        this.domainTTL = new StoredMapU256(domainTTLPointer);
        this.domainPendingOwner = new StoredMapU256(domainPendingOwnerPointer);
        this.domainPendingTimestamp = new StoredMapU256(domainPendingTimestampPointer);

        // Initialize subdomain storage
        this.subdomainExists = new StoredMapU256(subdomainExistsPointer);
        this.subdomainOwner = new StoredMapU256(subdomainOwnerPointer);
        this.subdomainParent = new StoredMapU256(subdomainParentPointer);
        this.subdomainTTL = new StoredMapU256(subdomainTTLPointer);

        // Initialize contenthash storage
        this.contenthashType = new StoredMapU256(contenthashTypePointer);
        this.contenthashData = new StoredMapU256(contenthashDataPointer);
    }

    // -------------------------------------------------------------------------
    // Deployment Initialization
    // -------------------------------------------------------------------------
    public override onDeployment(calldata: Calldata): void {
        // Read optional treasury address from calldata
        const treasuryAddr = calldata.readStringWithLength();
        if (treasuryAddr.length > 0) {
            this.treasuryAddress.value = treasuryAddr;
        } else {
            this.treasuryAddress.value = Blockchain.tx.origin.p2tr();
        }

        // Set default price
        this.domainPriceSats.set(u256.Zero, u256.fromU64(DEFAULT_DOMAIN_PRICE_SATS));

        // Reserve 'opnet.btc' for deployer
        const opnetDomainKey = this.getDomainKeyU256(RESERVED_DOMAIN);
        const blockNumber = Blockchain.block.number;
        const deployer = Blockchain.tx.origin;

        this.domainExists.set(opnetDomainKey, u256.One);
        this.domainOwner.set(opnetDomainKey, this._addressToU256(deployer));
        this.domainCreated.set(opnetDomainKey, u256.fromU64(blockNumber));
        this.domainTTL.set(opnetDomainKey, u256.fromU64(DEFAULT_TTL));

        this.emitEvent(new DomainRegisteredEvent(opnetDomainKey, deployer, blockNumber));
    }

    // =========================================================================
    // ADMIN METHODS (Owner Only)
    // =========================================================================

    /**
     * Set the treasury address for receiving payments.
     */
    @method({ name: 'treasuryAddress', type: ABIDataTypes.STRING })
    @emit('TreasuryChanged')
    public setTreasuryAddress(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const newAddress = calldata.readStringWithLength();
        if (newAddress.length == 0) {
            throw new Revert('Invalid treasury address');
        }

        this.validateBitcoinAddress(newAddress);

        const oldAddressHash = this.stringToU256Hash(this.treasuryAddress.value);
        const newAddressHash = this.stringToU256Hash(newAddress);

        this.treasuryAddress.value = newAddress;

        this.emitEvent(
            new TreasuryChangedEvent(oldAddressHash, newAddressHash, Blockchain.block.number),
        );

        return new BytesWriter(0);
    }

    /**
     * Set the base price for registering domains.
     */
    @method({ name: 'priceSats', type: ABIDataTypes.UINT64 })
    @emit('DomainPriceChanged')
    public setDomainPrice(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const newPrice = calldata.readU64();
        const oldPrice = this.domainPriceSats.get(u256.Zero).toU64();

        this.domainPriceSats.set(u256.Zero, u256.fromU64(newPrice));

        this.emitEvent(new DomainPriceChangedEvent(oldPrice, newPrice, Blockchain.block.number));

        return new BytesWriter(0);
    }

    // =========================================================================
    // DOMAIN REGISTRATION METHODS
    // =========================================================================

    /**
     * Register a new .btc domain.
     * @param calldata Contains domain name (without .btc suffix)
     */
    @method({ name: 'domainName', type: ABIDataTypes.STRING })
    @emit('DomainRegistered')
    public registerDomain(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();

        // Validate domain name
        this.validateDomainName(domainName);

        // Check if reserved
        if (domainName == RESERVED_DOMAIN) {
            throw new Revert('Domain is reserved');
        }

        const domainKey = this.getDomainKeyU256(domainName);

        // Check if already exists
        if (!this.domainExists.get(domainKey).isZero()) {
            throw new Revert('Domain already exists');
        }

        // Calculate and verify payment (premium pricing for short domains)
        const price = this.calculateDomainPrice(domainName);
        this.verifyPayment(price);

        // Register domain
        const blockNumber = Blockchain.block.number;
        const sender = Blockchain.tx.sender;

        this.domainExists.set(domainKey, u256.One);
        this.domainOwner.set(domainKey, this._addressToU256(sender));
        this.domainCreated.set(domainKey, u256.fromU64(blockNumber));
        this.domainTTL.set(domainKey, u256.fromU64(DEFAULT_TTL));

        this.emitEvent(new DomainRegisteredEvent(domainKey, sender, blockNumber));

        return new BytesWriter(0);
    }

    // =========================================================================
    // DOMAIN TRANSFER METHODS (Two-Step)
    // =========================================================================

    /**
     * Initiate transfer of domain ownership.
     */
    @method(
        { name: 'domainName', type: ABIDataTypes.STRING },
        { name: 'newOwner', type: ABIDataTypes.ADDRESS },
    )
    @emit('DomainTransferInitiated')
    public initiateTransfer(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const newOwner = calldata.readAddress();

        const domainKey = this.getDomainKeyU256(domainName);

        // Verify caller is owner
        this.requireDomainOwner(domainKey);

        // Validate new owner
        if (newOwner.equals(Address.zero())) {
            throw new Revert('Invalid new owner');
        }

        // Set pending transfer
        const blockNumber = Blockchain.block.number;
        this.domainPendingOwner.set(domainKey, this._addressToU256(newOwner));
        this.domainPendingTimestamp.set(domainKey, u256.fromU64(blockNumber));

        this.emitEvent(
            new DomainTransferInitiatedEvent(
                domainKey,
                Blockchain.tx.sender,
                newOwner,
                blockNumber,
            ),
        );

        return new BytesWriter(0);
    }

    /**
     * Accept a pending domain transfer.
     */
    @method({ name: 'domainName', type: ABIDataTypes.STRING })
    @emit('DomainTransferCompleted')
    public acceptTransfer(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const domainKey = this.getDomainKeyU256(domainName);

        // Verify pending transfer exists
        const pendingOwner = this._u256ToAddress(this.domainPendingOwner.get(domainKey));
        if (pendingOwner.equals(Address.zero())) {
            throw new Revert('No pending transfer');
        }

        // Verify caller is pending owner
        if (!Blockchain.tx.sender.equals(pendingOwner)) {
            throw new Revert('Not pending owner');
        }

        // Complete transfer
        const previousOwner = this._u256ToAddress(this.domainOwner.get(domainKey));
        const blockNumber = Blockchain.block.number;

        this.domainOwner.set(domainKey, this._addressToU256(pendingOwner));
        this.domainPendingOwner.set(domainKey, u256.Zero);
        this.domainPendingTimestamp.set(domainKey, u256.Zero);

        this.emitEvent(
            new DomainTransferCompletedEvent(domainKey, previousOwner, pendingOwner, blockNumber),
        );

        return new BytesWriter(0);
    }

    /**
     * Cancel a pending domain transfer.
     */
    @method({ name: 'domainName', type: ABIDataTypes.STRING })
    @emit('DomainTransferCancelled')
    public cancelTransfer(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const domainKey = this.getDomainKeyU256(domainName);

        // Verify caller is owner
        this.requireDomainOwner(domainKey);

        // Verify pending transfer exists
        if (this.domainPendingOwner.get(domainKey).isZero()) {
            throw new Revert('No pending transfer');
        }

        // Clear pending transfer
        this.domainPendingOwner.set(domainKey, u256.Zero);
        this.domainPendingTimestamp.set(domainKey, u256.Zero);

        this.emitEvent(
            new DomainTransferCancelledEvent(
                domainKey,
                Blockchain.tx.sender,
                Blockchain.block.number,
            ),
        );

        return new BytesWriter(0);
    }

    /**
     * Direct transfer of domain ownership (single transaction).
     * Owner can directly transfer without requiring recipient acceptance.
     */
    @method(
        { name: 'domainName', type: ABIDataTypes.STRING },
        { name: 'newOwner', type: ABIDataTypes.ADDRESS },
    )
    @emit('DomainTransferCompleted')
    public transferDomain(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const newOwner = calldata.readAddress();

        const domainKey = this.getDomainKeyU256(domainName);

        // Verify caller is owner
        this.requireDomainOwner(domainKey);

        // Validate new owner
        if (newOwner.equals(Address.zero())) {
            throw new Revert('Invalid new owner');
        }

        // Cannot transfer to self
        if (newOwner.equals(Blockchain.tx.sender)) {
            throw new Revert('Cannot transfer to self');
        }

        // Get current owner for event
        const previousOwner = this._u256ToAddress(this.domainOwner.get(domainKey));
        const blockNumber = Blockchain.block.number;

        // Clear any pending transfer
        this.domainPendingOwner.set(domainKey, u256.Zero);
        this.domainPendingTimestamp.set(domainKey, u256.Zero);

        // Transfer ownership
        this.domainOwner.set(domainKey, this._addressToU256(newOwner));

        this.emitEvent(
            new DomainTransferCompletedEvent(domainKey, previousOwner, newOwner, blockNumber),
        );

        return new BytesWriter(0);
    }

    /**
     * Transfer domain ownership via signature (gasless transfer).
     * Allows owner to sign a transfer message off-chain for a third party to execute.
     * @param ownerAddress - Current owner's address (32 bytes)
     * @param ownerTweakedPublicKey - Owner's tweaked public key for signature verification
     * @param domainName - Domain to transfer
     * @param newOwner - Recipient address
     * @param deadline - Block number deadline for signature validity
     * @param signature - 64-byte Schnorr signature
     */
    @method(
        { name: 'ownerAddress', type: ABIDataTypes.BYTES32 },
        { name: 'ownerTweakedPublicKey', type: ABIDataTypes.BYTES32 },
        { name: 'domainName', type: ABIDataTypes.STRING },
        { name: 'newOwner', type: ABIDataTypes.ADDRESS },
        { name: 'deadline', type: ABIDataTypes.UINT64 },
        { name: 'signature', type: ABIDataTypes.BYTES },
    )
    @emit('DomainTransferCompleted')
    public transferDomainBySignature(calldata: Calldata): BytesWriter {
        const ownerAddressBytes = calldata.readBytesArray(ADDRESS_BYTE_LENGTH);
        const ownerTweakedPublicKey = calldata.readBytesArray(ADDRESS_BYTE_LENGTH);

        const owner = new ExtendedAddress(ownerTweakedPublicKey, ownerAddressBytes);

        const domainName = calldata.readStringWithLength();
        const newOwner = calldata.readAddress();
        const deadline = calldata.readU64();
        const signature = calldata.readBytesWithLength();

        // Check signature length (Schnorr = 64 bytes)
        if (signature.length !== 64) {
            throw new Revert('Invalid signature length');
        }

        // Check deadline
        if (Blockchain.block.number > deadline) {
            throw new Revert('Signature expired');
        }

        const domainKey = this.getDomainKeyU256(domainName);

        // Verify domain exists
        if (this.domainExists.get(domainKey).isZero()) {
            throw new Revert('Domain does not exist');
        }

        // Verify the provided owner address matches the domain owner
        const storedOwner = this._u256ToAddress(this.domainOwner.get(domainKey));
        if (!storedOwner.equals(owner)) {
            throw new Revert('Not domain owner');
        }

        // Validate new owner
        if (newOwner.equals(Address.zero())) {
            throw new Revert('Invalid new owner');
        }

        if (newOwner.equals(storedOwner)) {
            throw new Revert('Cannot transfer to self');
        }

        // Build message hash for signature verification
        // Structure: sha256(domainKey + newOwner + deadline)
        const messageData = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + U64_BYTE_LENGTH,
        );
        messageData.writeU256(domainKey);
        messageData.writeAddress(newOwner);
        messageData.writeU64(deadline);

        const messageHash = Blockchain.sha256(messageData.getBuffer());

        // Verify signature
        if (!Blockchain.verifySignature(owner, signature, messageHash)) {
            throw new Revert('Invalid signature');
        }

        const blockNumber = Blockchain.block.number;

        // Clear any pending transfer
        this.domainPendingOwner.set(domainKey, u256.Zero);
        this.domainPendingTimestamp.set(domainKey, u256.Zero);

        // Transfer ownership
        this.domainOwner.set(domainKey, this._addressToU256(newOwner));

        this.emitEvent(
            new DomainTransferCompletedEvent(domainKey, storedOwner, newOwner, blockNumber),
        );

        return new BytesWriter(0);
    }

    // =========================================================================
    // SUBDOMAIN METHODS
    // =========================================================================

    /**
     * Create a subdomain under a domain you own.
     */
    @method(
        { name: 'parentDomain', type: ABIDataTypes.STRING },
        { name: 'subdomainLabel', type: ABIDataTypes.STRING },
        { name: 'subdomainOwner', type: ABIDataTypes.ADDRESS },
    )
    @emit('SubdomainCreated')
    public createSubdomain(calldata: Calldata): BytesWriter {
        const parentDomain = calldata.readStringWithLength();
        const subdomainLabel = calldata.readStringWithLength();
        const subdomainOwner = calldata.readAddress();

        // Validate subdomain label
        this.validateSubdomainLabel(subdomainLabel);

        const parentKey = this.getDomainKeyU256(parentDomain);

        // Verify parent domain exists
        if (this.domainExists.get(parentKey).isZero()) {
            throw new Revert('Parent domain does not exist');
        }

        // Verify caller owns parent domain
        this.requireDomainOwner(parentKey);

        // Generate full subdomain key: "label.parent"
        const fullName = subdomainLabel + '.' + parentDomain;

        // Validate full name length (DNS standard max is 253)
        if (fullName.length > <i32>MAX_FULL_NAME_LENGTH) {
            throw new Revert('Full name exceeds maximum length');
        }

        const subdomainKey = this.getSubdomainKeyU256(fullName);

        // Check if subdomain already exists
        if (!this.subdomainExists.get(subdomainKey).isZero()) {
            throw new Revert('Subdomain already exists');
        }

        // Determine owner (default to caller if zero address)
        const owner = subdomainOwner.equals(Address.zero()) ? Blockchain.tx.sender : subdomainOwner;

        const blockNumber = Blockchain.block.number;

        // Register subdomain
        this.subdomainExists.set(subdomainKey, u256.One);
        this.subdomainOwner.set(subdomainKey, this._addressToU256(owner));
        this.subdomainParent.set(subdomainKey, parentKey);
        this.subdomainTTL.set(subdomainKey, u256.fromU64(DEFAULT_TTL));

        this.emitEvent(new SubdomainCreatedEvent(parentKey, subdomainKey, owner, blockNumber));

        return new BytesWriter(0);
    }

    /**
     * Delete a subdomain. Only parent domain owner can delete.
     */
    @method(
        { name: 'parentDomain', type: ABIDataTypes.STRING },
        { name: 'subdomainLabel', type: ABIDataTypes.STRING },
    )
    @emit('SubdomainDeleted')
    public deleteSubdomain(calldata: Calldata): BytesWriter {
        const parentDomain = calldata.readStringWithLength();
        const subdomainLabel = calldata.readStringWithLength();

        const parentKey = this.getDomainKeyU256(parentDomain);

        // Verify caller owns parent domain
        this.requireDomainOwner(parentKey);

        const fullName = subdomainLabel + '.' + parentDomain;
        const subdomainKey = this.getSubdomainKeyU256(fullName);

        // Verify subdomain exists
        if (this.subdomainExists.get(subdomainKey).isZero()) {
            throw new Revert('Subdomain does not exist');
        }

        // Clear subdomain data
        this.subdomainExists.set(subdomainKey, u256.Zero);
        this.subdomainOwner.set(subdomainKey, u256.Zero);
        this.subdomainParent.set(subdomainKey, u256.Zero);
        this.subdomainTTL.set(subdomainKey, u256.Zero);

        // Clear contenthash if set
        this.contenthashType.set(subdomainKey, u256.Zero);
        this.contenthashData.set(subdomainKey, u256.Zero);

        this.emitEvent(new SubdomainDeletedEvent(parentKey, subdomainKey, Blockchain.block.number));

        return new BytesWriter(0);
    }

    // =========================================================================
    // CONTENTHASH METHODS
    // =========================================================================

    /**
     * Set contenthash for a domain or subdomain using CIDv0 (Qm...).
     */
    @method({ name: 'name', type: ABIDataTypes.STRING }, { name: 'cid', type: ABIDataTypes.STRING })
    @emit('ContenthashChanged')
    public setContenthashCIDv0(calldata: Calldata): BytesWriter {
        const name = calldata.readStringWithLength();
        const cid = calldata.readStringWithLength();

        this.validateCIDv0(cid);

        const nameKey = this.resolveNameKey(name);
        this.requireNameOwner(name, nameKey);

        // Store type and string CID
        this.contenthashType.set(nameKey, u256.fromU32(<u32>CONTENTHASH_TYPE_CIDv0));

        const keyBytes = this.getNameKeyBytes(name);
        const cidStorage = new AdvancedStoredString(
            contenthashStringPointer,
            keyBytes,
            MAX_CONTENTHASH_LENGTH,
        );
        cidStorage.value = cid;

        this.emitEvent(
            new ContenthashChangedEvent(nameKey, CONTENTHASH_TYPE_CIDv0, Blockchain.block.number),
        );

        return new BytesWriter(0);
    }

    /**
     * Set contenthash for a domain or subdomain using CIDv1 (bafy...).
     */
    @method({ name: 'name', type: ABIDataTypes.STRING }, { name: 'cid', type: ABIDataTypes.STRING })
    @emit('ContenthashChanged')
    public setContenthashCIDv1(calldata: Calldata): BytesWriter {
        const name = calldata.readStringWithLength();
        const cid = calldata.readStringWithLength();

        this.validateCIDv1(cid);

        const nameKey = this.resolveNameKey(name);
        this.requireNameOwner(name, nameKey);

        this.contenthashType.set(nameKey, u256.fromU32(<u32>CONTENTHASH_TYPE_CIDv1));

        const keyBytes = this.getNameKeyBytes(name);
        const cidStorage = new AdvancedStoredString(
            contenthashStringPointer,
            keyBytes,
            MAX_CONTENTHASH_LENGTH,
        );
        cidStorage.value = cid;

        this.emitEvent(
            new ContenthashChangedEvent(nameKey, CONTENTHASH_TYPE_CIDv1, Blockchain.block.number),
        );

        return new BytesWriter(0);
    }

    /**
     * Set contenthash for a domain or subdomain using IPNS (k...).
     */
    @method(
        { name: 'name', type: ABIDataTypes.STRING },
        { name: 'ipnsId', type: ABIDataTypes.STRING },
    )
    @emit('ContenthashChanged')
    public setContenthashIPNS(calldata: Calldata): BytesWriter {
        const name = calldata.readStringWithLength();
        const ipnsId = calldata.readStringWithLength();

        this.validateIPNS(ipnsId);

        const nameKey = this.resolveNameKey(name);
        this.requireNameOwner(name, nameKey);

        this.contenthashType.set(nameKey, u256.fromU32(<u32>CONTENTHASH_TYPE_IPNS));

        const keyBytes = this.getNameKeyBytes(name);
        const ipnsStorage = new AdvancedStoredString(
            contenthashStringPointer,
            keyBytes,
            MAX_CONTENTHASH_LENGTH,
        );
        ipnsStorage.value = ipnsId;

        this.emitEvent(
            new ContenthashChangedEvent(nameKey, CONTENTHASH_TYPE_IPNS, Blockchain.block.number),
        );

        return new BytesWriter(0);
    }

    /**
     * Set contenthash for a domain or subdomain using raw SHA-256 hash.
     */
    @method(
        { name: 'name', type: ABIDataTypes.STRING },
        { name: 'hash', type: ABIDataTypes.BYTES32 },
    )
    @emit('ContenthashChanged')
    public setContenthashSHA256(calldata: Calldata): BytesWriter {
        const name = calldata.readStringWithLength();
        const hash = calldata.readU256();

        if (hash.isZero()) {
            throw new Revert('Hash cannot be zero');
        }

        const nameKey = this.resolveNameKey(name);
        this.requireNameOwner(name, nameKey);

        this.contenthashType.set(nameKey, u256.fromU32(<u32>CONTENTHASH_TYPE_SHA256));
        this.contenthashData.set(nameKey, hash);

        this.emitEvent(
            new ContenthashChangedEvent(nameKey, CONTENTHASH_TYPE_SHA256, Blockchain.block.number),
        );

        return new BytesWriter(0);
    }

    /**
     * Clear contenthash for a domain or subdomain.
     */
    @method({ name: 'name', type: ABIDataTypes.STRING })
    @emit('ContenthashCleared')
    public clearContenthash(calldata: Calldata): BytesWriter {
        const name = calldata.readStringWithLength();

        const nameKey = this.resolveNameKey(name);
        this.requireNameOwner(name, nameKey);

        // Verify contenthash exists
        if (this.contenthashType.get(nameKey).isZero()) {
            throw new Revert('No contenthash set');
        }

        // Clear contenthash
        this.contenthashType.set(nameKey, u256.Zero);
        this.contenthashData.set(nameKey, u256.Zero);

        // Clear string storage
        const keyBytes = this.getNameKeyBytes(name);
        const cidStorage = new AdvancedStoredString(
            contenthashStringPointer,
            keyBytes,
            MAX_CONTENTHASH_LENGTH,
        );
        cidStorage.value = '';

        this.emitEvent(new ContenthashClearedEvent(nameKey, Blockchain.block.number));

        return new BytesWriter(0);
    }

    // =========================================================================
    // TTL METHODS
    // =========================================================================

    /**
     * Set TTL for a domain or subdomain.
     */
    @method({ name: 'name', type: ABIDataTypes.STRING }, { name: 'ttl', type: ABIDataTypes.UINT64 })
    @emit('TTLChanged')
    public setTTL(calldata: Calldata): BytesWriter {
        const name = calldata.readStringWithLength();
        const newTTL = calldata.readU64();

        if (newTTL < MIN_TTL || newTTL > MAX_TTL) {
            throw new Revert('TTL out of range');
        }

        const nameKey = this.resolveNameKey(name);
        this.requireNameOwner(name, nameKey);

        // Get old TTL
        let oldTTL: u64;
        if (this.isSubdomain(name)) {
            oldTTL = this.subdomainTTL.get(nameKey).toU64();
            this.subdomainTTL.set(nameKey, u256.fromU64(newTTL));
        } else {
            oldTTL = this.domainTTL.get(nameKey).toU64();
            this.domainTTL.set(nameKey, u256.fromU64(newTTL));
        }

        this.emitEvent(new TTLChangedEvent(nameKey, oldTTL, newTTL, Blockchain.block.number));

        return new BytesWriter(0);
    }

    // =========================================================================
    // VIEW METHODS
    // =========================================================================

    /**
     * Get domain information.
     */
    @method({ name: 'domainName', type: ABIDataTypes.STRING })
    @returns(
        { name: 'exists', type: ABIDataTypes.BOOL },
        { name: 'owner', type: ABIDataTypes.ADDRESS },
        { name: 'createdAt', type: ABIDataTypes.UINT64 },
        { name: 'ttl', type: ABIDataTypes.UINT64 },
    )
    public getDomain(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const domainKey = this.getDomainKeyU256(domainName);

        const exists = !this.domainExists.get(domainKey).isZero();
        const owner = exists
            ? this._u256ToAddress(this.domainOwner.get(domainKey))
            : Address.zero();
        const createdAt = exists ? this.domainCreated.get(domainKey).toU64() : <u64>0;
        const ttl = exists ? this.domainTTL.get(domainKey).toU64() : <u64>0;

        const response = new BytesWriter(1 + 32 + 8 + 8);
        response.writeBoolean(exists);
        response.writeAddress(owner);
        response.writeU64(createdAt);
        response.writeU64(ttl);

        return response;
    }

    /**
     * Get subdomain information.
     */
    @method({ name: 'fullName', type: ABIDataTypes.STRING })
    @returns(
        { name: 'exists', type: ABIDataTypes.BOOL },
        { name: 'owner', type: ABIDataTypes.ADDRESS },
        { name: 'parentHash', type: ABIDataTypes.BYTES32 },
        { name: 'ttl', type: ABIDataTypes.UINT64 },
    )
    public getSubdomain(calldata: Calldata): BytesWriter {
        const fullName = calldata.readStringWithLength();
        const subdomainKey = this.getSubdomainKeyU256(fullName);

        const exists = !this.subdomainExists.get(subdomainKey).isZero();
        const owner = exists
            ? this._u256ToAddress(this.subdomainOwner.get(subdomainKey))
            : Address.zero();
        const parentHash = exists ? this.subdomainParent.get(subdomainKey) : u256.Zero;
        const ttl = exists ? this.subdomainTTL.get(subdomainKey).toU64() : <u64>0;

        const response = new BytesWriter(1 + 32 + 32 + 8);
        response.writeBoolean(exists);
        response.writeAddress(owner);
        response.writeU256(parentHash);
        response.writeU64(ttl);

        return response;
    }

    /**
     * Get contenthash for a name.
     */
    @method({ name: 'name', type: ABIDataTypes.STRING })
    @returns(
        { name: 'hashType', type: ABIDataTypes.UINT8 },
        { name: 'hashData', type: ABIDataTypes.BYTES32 },
        { name: 'hashString', type: ABIDataTypes.STRING },
    )
    public getContenthash(calldata: Calldata): BytesWriter {
        const name = calldata.readStringWithLength();
        const nameKey = this.resolveNameKey(name);

        const hashType = <u8>this.contenthashType.get(nameKey).toU32();
        let hashData = u256.Zero;
        let hashString = '';

        if (hashType == CONTENTHASH_TYPE_SHA256) {
            hashData = this.contenthashData.get(nameKey);
        } else if (hashType != 0) {
            const keyBytes = this.getNameKeyBytes(name);
            const cidStorage = new AdvancedStoredString(
                contenthashStringPointer,
                keyBytes,
                MAX_CONTENTHASH_LENGTH,
            );
            hashString = cidStorage.value;
        }

        const strBytes = Uint8Array.wrap(String.UTF8.encode(hashString));
        const response = new BytesWriter(1 + 32 + 4 + strBytes.length);
        response.writeU8(hashType);
        response.writeU256(hashData);
        response.writeStringWithLength(hashString);

        return response;
    }

    /**
     * Resolve a full name to its owner address.
     * Works for both domains and subdomains.
     */
    @method({ name: 'name', type: ABIDataTypes.STRING })
    @returns({ name: 'owner', type: ABIDataTypes.ADDRESS })
    public resolve(calldata: Calldata): BytesWriter {
        const name = calldata.readStringWithLength();
        const nameKey = this.resolveNameKey(name);

        let owner: Address;
        if (this.isSubdomain(name)) {
            if (this.subdomainExists.get(nameKey).isZero()) {
                owner = Address.zero();
            } else {
                owner = this._u256ToAddress(this.subdomainOwner.get(nameKey));
            }
        } else {
            if (this.domainExists.get(nameKey).isZero()) {
                owner = Address.zero();
            } else {
                owner = this._u256ToAddress(this.domainOwner.get(nameKey));
            }
        }

        const response = new BytesWriter(32);
        response.writeAddress(owner);

        return response;
    }

    /**
     * Get pending domain transfer info.
     */
    @method({ name: 'domainName', type: ABIDataTypes.STRING })
    @returns(
        { name: 'pendingOwner', type: ABIDataTypes.ADDRESS },
        { name: 'initiatedAt', type: ABIDataTypes.UINT64 },
    )
    public getPendingTransfer(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const domainKey = this.getDomainKeyU256(domainName);

        const pendingOwner = this._u256ToAddress(this.domainPendingOwner.get(domainKey));
        const initiatedAt = this.domainPendingTimestamp.get(domainKey).toU64();

        const response = new BytesWriter(32 + 8);
        response.writeAddress(pendingOwner);
        response.writeU64(initiatedAt);

        return response;
    }

    /**
     * Get current treasury address.
     */
    @method()
    @returns({ name: 'treasuryAddress', type: ABIDataTypes.STRING })
    public getTreasuryAddress(_: Calldata): BytesWriter {
        const addr = this.treasuryAddress.value;
        const addrBytes = Uint8Array.wrap(String.UTF8.encode(addr));

        const response = new BytesWriter(4 + addrBytes.length);
        response.writeStringWithLength(addr);

        return response;
    }

    /**
     * Get current domain price for a specific domain.
     */
    @method({ name: 'domainName', type: ABIDataTypes.STRING })
    @returns({ name: 'priceSats', type: ABIDataTypes.UINT64 })
    public getDomainPrice(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const price = this.calculateDomainPrice(domainName);

        const response = new BytesWriter(8);
        response.writeU64(price);

        return response;
    }

    /**
     * Get base domain price.
     */
    @method()
    @returns({ name: 'priceSats', type: ABIDataTypes.UINT64 })
    public getBaseDomainPrice(_: Calldata): BytesWriter {
        const response = new BytesWriter(8);
        response.writeU64(this.domainPriceSats.get(u256.Zero).toU64());

        return response;
    }

    // =========================================================================
    // INTERNAL HELPERS
    // =========================================================================

    /**
     * Convert Address to u256 for storage.
     */
    protected _addressToU256(addr: Address): u256 {
        return u256.fromUint8ArrayBE(addr);
    }

    /**
     * Convert u256 to Address.
     */
    protected _u256ToAddress(val: u256): Address {
        if (val.isZero()) {
            return Address.zero();
        }
        const bytes = val.toUint8Array(true);
        return Address.fromUint8Array(bytes);
    }

    private getDomainKeyU256(domainName: string): u256 {
        const lower = this.toLowerCase(domainName);
        const bytes = Uint8Array.wrap(String.UTF8.encode(lower));
        return u256.fromUint8ArrayBE(Blockchain.sha256(bytes));
    }

    private getSubdomainKeyU256(fullName: string): u256 {
        const lower = this.toLowerCase(fullName);
        const bytes = Uint8Array.wrap(String.UTF8.encode(lower));
        return u256.fromUint8ArrayBE(Blockchain.sha256(bytes));
    }

    private getNameKeyBytes(name: string): Uint8Array {
        const lower = this.toLowerCase(name);
        const bytes = Uint8Array.wrap(String.UTF8.encode(lower));
        const hash = Blockchain.sha256(bytes);
        return hash.slice(0, 30);
    }

    private resolveNameKey(name: string): u256 {
        if (this.isSubdomain(name)) {
            return this.getSubdomainKeyU256(name);
        }
        return this.getDomainKeyU256(name);
    }

    private stringToU256Hash(str: string): u256 {
        const bytes = Uint8Array.wrap(String.UTF8.encode(str));
        return u256.fromUint8ArrayBE(Blockchain.sha256(bytes));
    }

    private isSubdomain(name: string): boolean {
        // Subdomain has format: label.domain (at least one dot)
        for (let i: i32 = 0; i < name.length; i++) {
            if (name.charCodeAt(i) == 46) {
                // '.'
                return true;
            }
        }
        return false;
    }

    private toLowerCase(str: string): string {
        let result = '';
        for (let i: i32 = 0; i < str.length; i++) {
            const c = str.charCodeAt(i);
            // Convert uppercase to lowercase (A-Z -> a-z)
            if (c >= 65 && c <= 90) {
                result += String.fromCharCode(c + 32);
            } else {
                result += String.fromCharCode(c);
            }
        }
        return result;
    }

    private validateDomainName(domain: string): void {
        const len = domain.length;
        if (len < <i32>MIN_DOMAIN_LENGTH || len > <i32>MAX_DOMAIN_LENGTH) {
            throw new Revert('Domain must be 1-63 characters');
        }

        // Must start with alphanumeric
        const first = domain.charCodeAt(0);
        if (!this.isAlphanumeric(first)) {
            throw new Revert('Domain must start with alphanumeric');
        }

        // Must end with alphanumeric
        const last = domain.charCodeAt(len - 1);
        if (!this.isAlphanumeric(last)) {
            throw new Revert('Domain must end with alphanumeric');
        }

        // Only lowercase letters, digits, and hyphens allowed
        for (let i = 0; i < len; i++) {
            const c = domain.charCodeAt(i);
            const isLower = c >= 97 && c <= 122; // a-z
            const isUpper = c >= 65 && c <= 90; // A-Z (will be lowercased)
            const isDigit = c >= 48 && c <= 57; // 0-9
            const isHyphen = c == 45; // -

            if (!isLower && !isUpper && !isDigit && !isHyphen) {
                throw new Revert('Invalid character in domain');
            }
        }

        // No consecutive hyphens
        for (let i = 0; i < len - 1; i++) {
            if (domain.charCodeAt(i) == 45 && domain.charCodeAt(i + 1) == 45) {
                throw new Revert('No consecutive hyphens allowed');
            }
        }
    }

    private validateSubdomainLabel(label: string): void {
        const len = label.length;
        if (len < 1 || len > <i32>MAX_SUBDOMAIN_LENGTH) {
            throw new Revert('Subdomain label must be 1-63 characters');
        }

        // Same rules as domain
        const first = label.charCodeAt(0);
        if (!this.isAlphanumeric(first)) {
            throw new Revert('Subdomain must start with alphanumeric');
        }

        for (let i = 0; i < len; i++) {
            const c = label.charCodeAt(i);
            const isLower = c >= 97 && c <= 122;
            const isUpper = c >= 65 && c <= 90;
            const isDigit = c >= 48 && c <= 57;
            const isHyphen = c == 45;

            if (!isLower && !isUpper && !isDigit && !isHyphen) {
                throw new Revert('Invalid character in subdomain');
            }
        }
    }

    private isAlphanumeric(c: i32): boolean {
        return (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57);
    }

    private validateCIDv0(cid: string): void {
        const len = cid.length;
        if (len != 46) {
            throw new Revert('CIDv0 must be 46 characters');
        }
        // Must start with "Qm"
        if (cid.charCodeAt(0) != 81 || cid.charCodeAt(1) != 109) {
            throw new Revert('CIDv0 must start with Qm');
        }
    }

    private validateCIDv1(cid: string): void {
        const len = cid.length;
        if (len < 50 || len > <i32>MAX_CONTENTHASH_LENGTH) {
            throw new Revert('CIDv1 must be 50-128 characters');
        }
        // Must start with "baf"
        if (cid.charCodeAt(0) != 98 || cid.charCodeAt(1) != 97 || cid.charCodeAt(2) != 102) {
            throw new Revert('CIDv1 must start with baf');
        }
    }

    private validateIPNS(ipnsId: string): void {
        const len = ipnsId.length;
        if (len < 50 || len > <i32>MAX_CONTENTHASH_LENGTH) {
            throw new Revert('IPNS ID must be 50-128 characters');
        }
        // Must start with "k"
        if (ipnsId.charCodeAt(0) != 107) {
            throw new Revert('IPNS ID must start with k');
        }
    }

    private validateBitcoinAddress(address: string): void {
        const len = address.length;
        if (len < 42 || len > 62) {
            throw new Revert('Invalid address length');
        }
        // Must start with bc1p or bc1q
        if (
            address.charCodeAt(0) != 98 ||
            address.charCodeAt(1) != 99 ||
            address.charCodeAt(2) != 49
        ) {
            throw new Revert('Address must start with bc1');
        }
        const fourth = address.charCodeAt(3);
        if (fourth != 112 && fourth != 113) {
            throw new Revert('Address must be bc1p or bc1q');
        }
    }

    private calculateDomainPrice(domainName: string): u64 {
        const lowerName = this.toLowerCase(domainName);
        const len = lowerName.length;
        const basePrice = this.domainPriceSats.get(u256.Zero).toU64();

        // Check TIER 0 first - Ultra Legendary (10 BTC)
        if (this.isInPremiumList(lowerName, PREMIUM_TIER_0_DOMAINS)) {
            return PREMIUM_TIER_0_PRICE_SATS;
        }

        // 1-char domains are always Tier 1 (1.5 BTC) - most valuable
        if (len == 1) {
            return PREMIUM_TIER_1_PRICE_SATS;
        }

        // 2-char domains are always Tier 2 (0.25 BTC)
        if (len == 2) {
            return PREMIUM_TIER_2_PRICE_SATS;
        }

        // Check premium keyword lists (highest tier match wins)
        if (this.isInPremiumList(lowerName, PREMIUM_TIER_1_DOMAINS)) {
            return PREMIUM_TIER_1_PRICE_SATS;
        }

        if (this.isInPremiumList(lowerName, PREMIUM_TIER_2_DOMAINS)) {
            return PREMIUM_TIER_2_PRICE_SATS;
        }

        if (len == 3) {
            return PREMIUM_TIER_3_PRICE_SATS;
        }

        if (this.isInPremiumList(lowerName, PREMIUM_TIER_3_DOMAINS)) {
            return PREMIUM_TIER_3_PRICE_SATS;
        }

        if (len == 4) {
            return PREMIUM_TIER_4_PRICE_SATS;
        }

        if (this.isInPremiumList(lowerName, PREMIUM_TIER_4_DOMAINS)) {
            return PREMIUM_TIER_4_PRICE_SATS;
        }

        if (this.isInPremiumList(lowerName, PREMIUM_TIER_5_DOMAINS)) {
            return PREMIUM_TIER_4_PRICE_SATS;
        }

        if (this.isInPremiumList(lowerName, PREMIUM_TIER_6_DOMAINS)) {
            return PREMIUM_TIER_4_PRICE_SATS;
        }

        if (len == 5) {
            return PREMIUM_TIER_5_PRICE_SATS;
        }

        return basePrice;
    }

    private isInPremiumList(domainName: string, premiumList: string[]): boolean {
        for (let i: i32 = 0; i < premiumList.length; i++) {
            if (domainName == premiumList[i]) {
                return true;
            }
        }
        return false;
    }

    private verifyPayment(requiredSats: u64): void {
        if (!Blockchain.tx.origin.equals(Blockchain.tx.sender)) {
            throw new Revert('Contracts not allowed.');
        }

        const treasuryAddr = this.treasuryAddress.value;
        let totalPaid: u64 = 0;

        const outputs = Blockchain.tx.outputs;
        for (let i: i32 = 0; i < outputs.length; i++) {
            if (outputs[i].to == treasuryAddr) {
                totalPaid = SafeMath.add64(totalPaid, outputs[i].value);
            }
        }

        if (totalPaid < requiredSats) {
            throw new Revert('Insufficient payment');
        }
    }

    private requireDomainOwner(domainKey: u256): void {
        if (this.domainExists.get(domainKey).isZero()) {
            throw new Revert('Domain does not exist');
        }

        const owner = this._u256ToAddress(this.domainOwner.get(domainKey));
        if (!Blockchain.tx.sender.equals(owner)) {
            throw new Revert('Not domain owner');
        }
    }

    private requireNameOwner(name: string, nameKey: u256): void {
        if (this.isSubdomain(name)) {
            if (this.subdomainExists.get(nameKey).isZero()) {
                throw new Revert('Subdomain does not exist');
            }
            const owner = this._u256ToAddress(this.subdomainOwner.get(nameKey));
            if (!Blockchain.tx.sender.equals(owner)) {
                throw new Revert('Not subdomain owner');
            }
        } else {
            this.requireDomainOwner(nameKey);
        }
    }
}
