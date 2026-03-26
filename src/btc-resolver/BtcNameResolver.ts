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
    ON_OP20_RECEIVED_SELECTOR,
    OP20Utils,
    OP_NET,
    Revert,
    SafeMath,
    StoredString,
    TransferHelper,
    U256_BYTE_LENGTH,
    U64_BYTE_LENGTH,
} from '@btc-vision/btc-runtime/runtime';
import { SELECTOR_BYTE_LENGTH } from '@btc-vision/btc-runtime/runtime/utils/lengths';
import { StoredMapU256 } from '@btc-vision/btc-runtime/runtime/storage/maps/StoredMapU256';
import { AdvancedStoredString } from '@btc-vision/btc-runtime/runtime/storage/AdvancedStoredString';

import {
    ContenthashChangedEvent,
    ContenthashClearedEvent,
    ContractUpdatedEvent,
    DomainPriceChangedEvent,
    DomainRegisteredEvent,
    DomainRenewedEvent,
    DomainReservedEvent,
    DomainTransferCancelledEvent,
    DomainTransferCompletedEvent,
    DomainTransferInitiatedEvent,
    SubdomainCreatedEvent,
    SubdomainDeletedEvent,
    TreasuryChangedEvent,
    TTLChangedEvent,
} from './events/ResolverEvents';

import {
    AUCTION_DURATION_BLOCKS,
    BLOCKS_PER_YEAR,
    CONTENTHASH_TYPE_CIDv0,
    CONTENTHASH_TYPE_CIDv1,
    CONTENTHASH_TYPE_IPNS,
    CONTENTHASH_TYPE_SHA256,
    DEFAULT_DOMAIN_PRICE_SATS,
    DEFAULT_TTL,
    GRACE_PERIOD_BLOCKS,
    MAX_CONTENTHASH_LENGTH,
    MAX_DOMAIN_LENGTH,
    MAX_FULL_NAME_LENGTH,
    MAX_REGISTRATION_YEARS,
    MAX_SUBDOMAIN_LENGTH,
    MAX_TTL,
    MIN_DOMAIN_LENGTH,
    MIN_TTL,
    PREMIUM_RENEWAL_MIN_SATS,
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
    RESERVATION_FEE_ADDRESS,
    RESERVATION_FEE_SATS,
    RESERVATION_TIMEOUT_BLOCKS,
    RESERVED_DOMAIN,
} from './constants';

// =============================================================================
// Storage Pointer Allocation (Module Level - CRITICAL)
// =============================================================================

// Contract-level settings
const treasuryAddressPointer: u16 = Blockchain.nextPointer;
const domainPriceSatsPointer: u16 = Blockchain.nextPointer;
const deploymentBlockPointer: u16 = Blockchain.nextPointer;

// Domain storage
const domainExistsPointer: u16 = Blockchain.nextPointer;
const domainOwnerPointer: u16 = Blockchain.nextPointer;
const domainCreatedPointer: u16 = Blockchain.nextPointer;
const domainTTLPointer: u16 = Blockchain.nextPointer;
const domainExpiryPointer: u16 = Blockchain.nextPointer;
const domainAuctionStartPointer: u16 = Blockchain.nextPointer;

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

// Reservation storage
const domainReservationOwnerPointer: u16 = Blockchain.nextPointer;
const domainReservationBlockPointer: u16 = Blockchain.nextPointer;
const domainReservationYearsPointer: u16 = Blockchain.nextPointer;

// Domain nonce (for signature replay protection)
const domainPaidPriceSatsPointer: u16 = Blockchain.nextPointer;
const domainPaidPriceMotoPointer: u16 = Blockchain.nextPointer;
const domainGenerationPointer: u16 = Blockchain.nextPointer;
const subdomainGenerationPointer: u16 = Blockchain.nextPointer;
const domainNoncePointer: u16 = Blockchain.nextPointer;

// MOTO OP20 payment storage
const motoTokenAddressPointer: u16 = Blockchain.nextPointer;
const motoTierPricesPointer: u16 = Blockchain.nextPointer;
const motoBasePricePointer: u16 = Blockchain.nextPointer;
const motoEnabledPointer: u16 = Blockchain.nextPointer;

// Owner domain index (enumerable: get all domains by owner)
const ownerDomainCountPointer: u16 = Blockchain.nextPointer;
const ownerDomainAtIndexPointer: u16 = Blockchain.nextPointer;
const domainIndexInOwnerListPointer: u16 = Blockchain.nextPointer;

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
    private readonly deploymentBlock: StoredMapU256;

    // -------------------------------------------------------------------------
    // Domain Storage Maps
    // -------------------------------------------------------------------------
    private readonly domainExists: StoredMapU256;
    private readonly domainOwner: StoredMapU256;
    private readonly domainCreated: StoredMapU256;
    private readonly domainTTL: StoredMapU256;
    private readonly domainExpiry: StoredMapU256;
    private readonly domainAuctionStart: StoredMapU256;
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
    // Reservation Storage
    // -------------------------------------------------------------------------
    private readonly domainReservationOwner: StoredMapU256;
    private readonly domainReservationBlock: StoredMapU256;
    private readonly domainReservationYears: StoredMapU256;

    // -------------------------------------------------------------------------
    // Domain Nonce (signature replay protection)
    // -------------------------------------------------------------------------
    private readonly domainPaidPriceSats: StoredMapU256;
    private readonly domainPaidPriceMoto: StoredMapU256;
    private readonly domainGeneration: StoredMapU256;
    private readonly subdomainGeneration: StoredMapU256;
    private readonly domainNonce: StoredMapU256;

    // -------------------------------------------------------------------------
    // MOTO OP20 Payment Storage
    // -------------------------------------------------------------------------
    private readonly motoTokenAddress: StoredMapU256;
    private readonly motoTierPrices: StoredMapU256;
    private readonly motoBasePrice: StoredMapU256;
    private readonly motoEnabled: StoredMapU256;

    // -------------------------------------------------------------------------
    // Owner Domain Index (Enumerable)
    // -------------------------------------------------------------------------
    private readonly ownerDomainCount: StoredMapU256;
    private readonly ownerDomainAtIndex: StoredMapU256;
    private readonly domainIndexInOwnerList: StoredMapU256;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    public constructor() {
        super();

        // Initialize settings storage
        this.treasuryAddress = new StoredString(treasuryAddressPointer);
        this.domainPriceSats = new StoredMapU256(domainPriceSatsPointer);
        this.deploymentBlock = new StoredMapU256(deploymentBlockPointer);

        // Initialize domain storage
        this.domainExists = new StoredMapU256(domainExistsPointer);
        this.domainOwner = new StoredMapU256(domainOwnerPointer);
        this.domainCreated = new StoredMapU256(domainCreatedPointer);
        this.domainTTL = new StoredMapU256(domainTTLPointer);
        this.domainExpiry = new StoredMapU256(domainExpiryPointer);
        this.domainAuctionStart = new StoredMapU256(domainAuctionStartPointer);
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

        // Initialize reservation storage
        this.domainReservationOwner = new StoredMapU256(domainReservationOwnerPointer);
        this.domainReservationBlock = new StoredMapU256(domainReservationBlockPointer);
        this.domainReservationYears = new StoredMapU256(domainReservationYearsPointer);

        // Initialize nonce storage
        this.domainPaidPriceSats = new StoredMapU256(domainPaidPriceSatsPointer);
        this.domainPaidPriceMoto = new StoredMapU256(domainPaidPriceMotoPointer);
        this.domainGeneration = new StoredMapU256(domainGenerationPointer);
        this.subdomainGeneration = new StoredMapU256(subdomainGenerationPointer);
        this.domainNonce = new StoredMapU256(domainNoncePointer);

        // Initialize MOTO payment storage
        this.motoTokenAddress = new StoredMapU256(motoTokenAddressPointer);
        this.motoTierPrices = new StoredMapU256(motoTierPricesPointer);
        this.motoBasePrice = new StoredMapU256(motoBasePricePointer);
        this.motoEnabled = new StoredMapU256(motoEnabledPointer);

        // Initialize owner domain index
        this.ownerDomainCount = new StoredMapU256(ownerDomainCountPointer);
        this.ownerDomainAtIndex = new StoredMapU256(ownerDomainAtIndexPointer);
        this.domainIndexInOwnerList = new StoredMapU256(domainIndexInOwnerListPointer);
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------
    public override onUpdate(calldata: Calldata): void {
        super.onUpdate(calldata);
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

        // Store deployment block as default auction start for never-registered domains
        const blockNumber = Blockchain.block.number;
        this.deploymentBlock.set(u256.Zero, u256.fromU64(blockNumber));

        // Reserve 'opnet.btc' for deployer (never expires)
        const opnetDomainKey = this.getDomainKeyU256(RESERVED_DOMAIN);
        const deployer = Blockchain.tx.origin;

        this.domainExists.set(opnetDomainKey, u256.One);
        this.domainOwner.set(opnetDomainKey, this._addressToU256(deployer));
        this.domainCreated.set(opnetDomainKey, u256.fromU64(blockNumber));
        this.domainTTL.set(opnetDomainKey, u256.fromU64(DEFAULT_TTL));
        this.domainExpiry.set(opnetDomainKey, u256.fromU64(u64.MAX_VALUE - GRACE_PERIOD_BLOCKS));

        this._addDomainToOwner(this._addressToU256(deployer), opnetDomainKey);

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
        if (newPrice == 0) {
            throw new Revert('Price cannot be zero');
        }

        const oldPrice = this.domainPriceSats.get(u256.Zero).toU64();

        this.domainPriceSats.set(u256.Zero, u256.fromU64(newPrice));

        this.emitEvent(new DomainPriceChangedEvent(oldPrice, newPrice, Blockchain.block.number));

        return new BytesWriter(0);
    }

    /**
     * Mint any domain for free. Deployer only.
     * Bypasses payment, auction, and reservation. Respects expiry and availability.
     */
    @method(
        { name: 'domainName', type: ABIDataTypes.STRING },
        { name: 'years', type: ABIDataTypes.UINT64 },
        { name: 'owner', type: ABIDataTypes.ADDRESS },
    )
    @emit('DomainRegistered')
    public mintDomain(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const domainName = calldata.readStringWithLength();
        const years = calldata.readU64();
        const owner = calldata.readAddress();

        this.validateDomainName(domainName);

        if (years < 1 || years > MAX_REGISTRATION_YEARS) {
            throw new Revert('Years must be 1-10');
        }

        if (owner.equals(Address.zero())) {
            throw new Revert('Invalid owner');
        }

        const domainKey = this.getDomainKeyU256(domainName);
        const blockNumber = Blockchain.block.number;

        // Check availability
        const exists = !this.domainExists.get(domainKey).isZero();
        if (exists) {
            const expiry = this.domainExpiry.get(domainKey).toU64();
            const graceEnd = SafeMath.add64(expiry, GRACE_PERIOD_BLOCKS);
            if (blockNumber <= graceEnd) {
                throw new Revert('Domain is not available');
            }
            this.domainPendingOwner.set(domainKey, u256.Zero);
            this.domainPendingTimestamp.set(domainKey, u256.Zero);
            this._removeDomainFromOwner(this.domainOwner.get(domainKey), domainKey);
        }

        const expiryBlock = SafeMath.add64(blockNumber, SafeMath.mul64(BLOCKS_PER_YEAR, years));
        const ownerU256 = this._addressToU256(owner);

        this.domainExists.set(domainKey, u256.One);
        this.domainOwner.set(domainKey, ownerU256);
        this.domainCreated.set(domainKey, u256.fromU64(blockNumber));
        this.domainTTL.set(domainKey, u256.fromU64(DEFAULT_TTL));
        this.domainExpiry.set(domainKey, u256.fromU64(expiryBlock));
        this.domainAuctionStart.set(domainKey, u256.Zero);
        this.contenthashType.set(domainKey, u256.Zero);
        this.contenthashData.set(domainKey, u256.Zero);
        this.domainGeneration.set(
            domainKey,
            SafeMath.add(this.domainGeneration.get(domainKey), u256.One),
        );
        this.domainPaidPriceSats.set(domainKey, u256.fromU64(this.getPremiumTierPrice(domainName)));
        this.domainPaidPriceMoto.set(domainKey, u256.Zero);

        this._addDomainToOwner(ownerU256, domainKey);

        this.emitEvent(new DomainRegisteredEvent(domainKey, owner, blockNumber));

        return new BytesWriter(0);
    }

    /**
     * Airdrop domains to multiple addresses. Deployer only.
     * Takes an array of (domainName, years, owner) tuples.
     * Skips unavailable domains instead of reverting the whole batch.
     */
    @method({ name: 'entries', type: 'tuple(string,uint64,address)[]' })
    public airdropDomains(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const count = calldata.readU16();
        const blockNumber = Blockchain.block.number;
        let minted: u16 = 0;

        for (let i: u16 = 0; i < count; i++) {
            const domainName = calldata.readStringWithLength();
            const years = calldata.readU64();
            const owner = calldata.readAddress();

            if (years < 1 || years > MAX_REGISTRATION_YEARS) continue;
            if (owner.equals(Address.zero())) continue;
            if (!this.isValidDomainName(domainName)) continue;

            const domainKey = this.getDomainKeyU256(domainName);

            // Skip if domain is active or in grace
            const exists = !this.domainExists.get(domainKey).isZero();
            if (exists) {
                const expiry = this.domainExpiry.get(domainKey).toU64();
                const graceEnd = SafeMath.add64(expiry, GRACE_PERIOD_BLOCKS);
                if (blockNumber <= graceEnd) continue;
                this.domainPendingOwner.set(domainKey, u256.Zero);
                this.domainPendingTimestamp.set(domainKey, u256.Zero);
                this._removeDomainFromOwner(this.domainOwner.get(domainKey), domainKey);
            }

            const expiryBlock = SafeMath.add64(blockNumber, SafeMath.mul64(BLOCKS_PER_YEAR, years));
            const ownerU256 = this._addressToU256(owner);

            this.domainExists.set(domainKey, u256.One);
            this.domainOwner.set(domainKey, ownerU256);
            this.domainCreated.set(domainKey, u256.fromU64(blockNumber));
            this.domainTTL.set(domainKey, u256.fromU64(DEFAULT_TTL));
            this.domainExpiry.set(domainKey, u256.fromU64(expiryBlock));
            this.domainAuctionStart.set(domainKey, u256.Zero);
            this.contenthashType.set(domainKey, u256.Zero);
            this.contenthashData.set(domainKey, u256.Zero);
            this.domainGeneration.set(
                domainKey,
                SafeMath.add(this.domainGeneration.get(domainKey), u256.One),
            );
            this.domainPaidPriceSats.set(
                domainKey,
                u256.fromU64(this.getPremiumTierPrice(domainName)),
            );
            this.domainPaidPriceMoto.set(domainKey, u256.Zero);

            this._addDomainToOwner(ownerU256, domainKey);

            this.emitEvent(new DomainRegisteredEvent(domainKey, owner, blockNumber));
            minted++;
        }

        const response = new BytesWriter(2);
        response.writeU16(minted);
        return response;
    }

    // =========================================================================
    // CONTRACT UPDATE
    // =========================================================================

    /**
     * Update contract bytecode. Deployer only, EOA only.
     */
    @method(
        { name: 'sourceAddress', type: ABIDataTypes.ADDRESS },
        { name: 'updateCalldata', type: ABIDataTypes.BYTES },
    )
    @emit('ContractUpdated')
    public update(calldata: Calldata): BytesWriter {
        if (Blockchain.tx.sender !== Blockchain.tx.origin) {
            throw new Revert('Origin must be the sender');
        }

        if (Blockchain.isContract(Blockchain.tx.sender)) {
            throw new Revert('Sender must be EOA');
        }

        this.onlyDeployer(Blockchain.tx.sender);

        const address: Address = calldata.readAddress();
        const data: Uint8Array = calldata.readBytesWithLength();

        const writer = new BytesWriter(data.length);
        writer.writeBytes(data);

        Blockchain.updateContractFromExisting(address, writer);
        Blockchain.emit(new ContractUpdatedEvent(address));

        return new BytesWriter(0);
    }

    // =========================================================================
    // OP20 TOKEN METHODS
    // =========================================================================

    /**
     * OP20 safe transfer callback. Required to receive MOTO tokens.
     */
    @method(
        { name: 'operator', type: ABIDataTypes.ADDRESS },
        { name: 'from', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
        { name: 'data', type: ABIDataTypes.BYTES },
    )
    @returns({ name: 'selector', type: ABIDataTypes.BYTES4 })
    public onOP20Received(_calldata: Calldata): BytesWriter {
        const writer = new BytesWriter(SELECTOR_BYTE_LENGTH);
        writer.writeSelector(ON_OP20_RECEIVED_SELECTOR);
        return writer;
    }

    /**
     * Set the MOTO token contract address. Deployer only.
     */
    @method({ name: 'tokenAddress', type: ABIDataTypes.ADDRESS })
    public setMotoTokenAddress(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const tokenAddress = calldata.readAddress();
        this.motoTokenAddress.set(u256.Zero, this._addressToU256(tokenAddress));

        return new BytesWriter(0);
    }

    /**
     * Set MOTO price for a specific premium tier. Deployer only.
     * Tier 0-5 maps to premium tiers, tier 255 is the base/default price.
     */
    @method(
        { name: 'tier', type: ABIDataTypes.UINT8 },
        { name: 'price', type: ABIDataTypes.UINT256 },
    )
    public setMotoTierPrice(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const tier = calldata.readU8();
        const price = calldata.readU256();

        this.motoTierPrices.set(u256.fromU32(<u32>tier), price);

        return new BytesWriter(0);
    }

    /**
     * Set MOTO base price for non-premium domains (per year). Deployer only.
     */
    @method({ name: 'price', type: ABIDataTypes.UINT256 })
    public setMotoBasePrice(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const price = calldata.readU256();
        if (price.isZero()) {
            throw new Revert('Price cannot be zero');
        }
        this.motoBasePrice.set(u256.Zero, price);

        return new BytesWriter(0);
    }

    /**
     * Enable or disable MOTO payments. Deployer only. Disabled by default.
     */
    @method({ name: 'enabled', type: ABIDataTypes.BOOL })
    public setMotoEnabled(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const enabled = calldata.readBoolean();
        this.motoEnabled.set(u256.Zero, enabled ? u256.One : u256.Zero);

        return new BytesWriter(0);
    }

    /**
     * Get MOTO price for a specific premium tier.
     */
    @method({ name: 'tier', type: ABIDataTypes.UINT8 })
    @returns({ name: 'price', type: ABIDataTypes.UINT256 })
    public getMotoTierPrice(calldata: Calldata): BytesWriter {
        const tier = calldata.readU8();
        const price = this.motoTierPrices.get(u256.fromU32(<u32>tier));

        const response = new BytesWriter(32);
        response.writeU256(price);
        return response;
    }

    /**
     * Get MOTO base price per year.
     */
    @method()
    @returns({ name: 'price', type: ABIDataTypes.UINT256 })
    public getMotoBasePriceView(_calldata: Calldata): BytesWriter {
        const price = this.motoBasePrice.get(u256.Zero);

        const response = new BytesWriter(32);
        response.writeU256(price);
        return response;
    }

    /**
     * Get the MOTO token contract address.
     */
    @method()
    @returns({ name: 'tokenAddress', type: ABIDataTypes.ADDRESS })
    public getMotoTokenAddressView(_calldata: Calldata): BytesWriter {
        const addr = this._u256ToAddress(this.motoTokenAddress.get(u256.Zero));

        const response = new BytesWriter(ADDRESS_BYTE_LENGTH);
        response.writeAddress(addr);
        return response;
    }

    /**
     * Withdraw OP20 tokens held by this contract. Deployer only.
     */
    @method({ name: 'token', type: ABIDataTypes.ADDRESS })
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public withdrawOP20(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const token = calldata.readAddress();
        const balance = OP20Utils.balanceOf(token, Blockchain.contractAddress);

        if (!balance.isZero()) {
            TransferHelper.transfer(token, Blockchain.tx.sender, balance);
        }

        const response = new BytesWriter(1);
        response.writeBoolean(true);
        return response;
    }

    // =========================================================================
    // MOTO DOMAIN REGISTRATION & RENEWAL
    // =========================================================================

    /**
     * Register a domain paying with MOTO tokens instead of BTC.
     * Caller must have approved this contract to spend their MOTO tokens.
     */
    @method(
        { name: 'domainName', type: ABIDataTypes.STRING },
        { name: 'years', type: ABIDataTypes.UINT64 },
    )
    @emit('DomainRegistered')
    public registerDomainWithMoto(calldata: Calldata): BytesWriter {
        this.requireEOA();
        this.requireMotoEnabled();

        const domainName = calldata.readStringWithLength();
        const years = calldata.readU64();

        this.validateDomainName(domainName);

        if (domainName == RESERVED_DOMAIN) {
            throw new Revert('Domain is reserved');
        }

        if (years < 1 || years > MAX_REGISTRATION_YEARS) {
            throw new Revert('Years must be 1-10');
        }

        const domainKey = this.getDomainKeyU256(domainName);
        const blockNumber = Blockchain.block.number;

        // Check domain availability
        const exists = !this.domainExists.get(domainKey).isZero();
        if (exists) {
            const expiry = this.domainExpiry.get(domainKey).toU64();
            const graceEnd = SafeMath.add64(expiry, GRACE_PERIOD_BLOCKS);
            if (blockNumber <= graceEnd) {
                throw new Revert('Domain is not available');
            }
            this.domainPendingOwner.set(domainKey, u256.Zero);
            this.domainPendingTimestamp.set(domainKey, u256.Zero);
            this._removeDomainFromOwner(this.domainOwner.get(domainKey), domainKey);
        }

        const motoBase = this.motoBasePrice.get(u256.Zero);
        if (motoBase.isZero()) {
            throw new Revert('MOTO base price not set');
        }
        const motoAuctionPrice = this.getMotoFirstYearPrice(
            domainName,
            domainKey,
            blockNumber,
            motoBase,
        );

        let totalMotoPrice: u256;
        if (motoAuctionPrice > motoBase) {
            const motoTenPercent = SafeMath.div(motoAuctionPrice, u256.fromU64(10));
            const motoRenewalPerYear = motoTenPercent > motoBase ? motoTenPercent : motoBase;
            totalMotoPrice = SafeMath.add(
                motoAuctionPrice,
                SafeMath.mul(motoRenewalPerYear, u256.fromU64(years)),
            );
        } else {
            totalMotoPrice = SafeMath.mul(motoBase, u256.fromU64(years));
        }
        this.collectMotoPayment(totalMotoPrice);

        // Register domain
        const sender = Blockchain.tx.sender;
        const senderU256 = this._addressToU256(sender);
        const expiryBlock = SafeMath.add64(blockNumber, SafeMath.mul64(BLOCKS_PER_YEAR, years));

        this.domainExists.set(domainKey, u256.One);
        this.domainOwner.set(domainKey, senderU256);
        this.domainCreated.set(domainKey, u256.fromU64(blockNumber));
        this.domainTTL.set(domainKey, u256.fromU64(DEFAULT_TTL));
        this.domainExpiry.set(domainKey, u256.fromU64(expiryBlock));

        // Clear stale auction start so next expiry cycle computes a fresh one
        this.domainAuctionStart.set(domainKey, u256.Zero);

        this.contenthashType.set(domainKey, u256.Zero);
        this.contenthashData.set(domainKey, u256.Zero);
        this.domainGeneration.set(
            domainKey,
            SafeMath.add(this.domainGeneration.get(domainKey), u256.One),
        );
        this.domainPaidPriceSats.set(domainKey, u256.Zero);
        this.domainPaidPriceMoto.set(domainKey, motoAuctionPrice);

        this._addDomainToOwner(senderU256, domainKey);

        this.emitEvent(new DomainRegisteredEvent(domainKey, sender, blockNumber));

        return new BytesWriter(0);
    }

    /**
     * Renew a domain paying with MOTO tokens instead of BTC.
     */
    @method(
        { name: 'domainName', type: ABIDataTypes.STRING },
        { name: 'years', type: ABIDataTypes.UINT64 },
    )
    @emit('DomainRenewed')
    public renewDomainWithMoto(calldata: Calldata): BytesWriter {
        this.requireMotoEnabled();

        const domainName = calldata.readStringWithLength();
        const years = calldata.readU64();

        if (years < 1 || years > MAX_REGISTRATION_YEARS) {
            throw new Revert('Years must be 1-10');
        }

        const domainKey = this.getDomainKeyU256(domainName);
        const blockNumber = Blockchain.block.number;

        if (this.domainExists.get(domainKey).isZero()) {
            throw new Revert('Domain does not exist');
        }

        const owner = this._u256ToAddress(this.domainOwner.get(domainKey));
        if (!Blockchain.tx.sender.equals(owner)) {
            throw new Revert('Not domain owner');
        }

        const currentExpiry = this.domainExpiry.get(domainKey).toU64();
        const graceEnd = SafeMath.add64(currentExpiry, GRACE_PERIOD_BLOCKS);
        if (blockNumber > graceEnd) {
            throw new Revert('Domain expired past grace period');
        }

        const motoBase = this.motoBasePrice.get(u256.Zero);
        if (motoBase.isZero()) {
            throw new Revert('MOTO base price not set');
        }
        const motoPaid = this.domainPaidPriceMoto.get(domainKey);
        let totalMotoPrice: u256;
        if (motoPaid > motoBase) {
            const motoTenPercent = SafeMath.div(motoPaid, u256.fromU64(10));
            const motoRenewalPerYear = motoTenPercent > motoBase ? motoTenPercent : motoBase;
            totalMotoPrice = SafeMath.mul(motoRenewalPerYear, u256.fromU64(years));
        } else {
            totalMotoPrice = SafeMath.mul(motoBase, u256.fromU64(years));
        }
        this.collectMotoPayment(totalMotoPrice);

        const extensionBase = blockNumber > currentExpiry ? blockNumber : currentExpiry;
        const newExpiry = SafeMath.add64(extensionBase, SafeMath.mul64(BLOCKS_PER_YEAR, years));
        this.domainExpiry.set(domainKey, u256.fromU64(newExpiry));

        this.emitEvent(new DomainRenewedEvent(domainKey, owner, newExpiry, blockNumber));

        return new BytesWriter(0);
    }

    // =========================================================================
    // DOMAIN REGISTRATION METHODS (Two-Step BTC Flow)
    // =========================================================================

    /**
     * Step 1: Reserve a domain name.
     * Pays a small reservation fee (2k sats) to lock the name for 5 blocks.
     * EOA only — contracts cannot reserve domains.
     */
    @method(
        { name: 'domainName', type: ABIDataTypes.STRING },
        { name: 'years', type: ABIDataTypes.UINT64 },
    )
    @emit('DomainReserved')
    public reserveDomain(calldata: Calldata): BytesWriter {
        this.requireEOA();

        const domainName = calldata.readStringWithLength();
        const years = calldata.readU64();

        this.validateDomainName(domainName);

        if (domainName == RESERVED_DOMAIN) {
            throw new Revert('Domain is reserved');
        }

        if (years < 1 || years > MAX_REGISTRATION_YEARS) {
            throw new Revert('Years must be 1-10');
        }

        const domainKey = this.getDomainKeyU256(domainName);
        const blockNumber = Blockchain.block.number;

        // Check domain availability: must not exist OR must be fully expired (past grace)
        const exists = !this.domainExists.get(domainKey).isZero();
        if (exists) {
            const expiry = this.domainExpiry.get(domainKey).toU64();
            const graceEnd = SafeMath.add64(expiry, GRACE_PERIOD_BLOCKS);
            if (blockNumber <= graceEnd) {
                throw new Revert('Domain is not available');
            }
        }

        // Check no active reservation exists (or it expired)
        const existingReservationBlock = this.domainReservationBlock.get(domainKey).toU64();
        if (existingReservationBlock > 0) {
            const reservationExpiry = SafeMath.add64(
                existingReservationBlock,
                RESERVATION_TIMEOUT_BLOCKS,
            );
            if (blockNumber <= reservationExpiry) {
                throw new Revert('Domain is already reserved');
            }
        }

        // Verify reservation fee payment to hardcoded address
        this.verifyReservationFee();

        // Store reservation
        const sender = Blockchain.tx.sender;
        this.domainReservationOwner.set(domainKey, this._addressToU256(sender));
        this.domainReservationBlock.set(domainKey, u256.fromU64(blockNumber));
        this.domainReservationYears.set(domainKey, u256.fromU64(years));

        this.emitEvent(new DomainReservedEvent(domainKey, sender, years, blockNumber));

        return new BytesWriter(0);
    }

    /**
     * Step 2: Complete domain registration after reservation.
     * Must be called by the reserver, at least 1 block after reservation, within 5 blocks.
     * Pays full domain price minus the 2k sat reservation fee.
     * EOA only — contracts cannot complete registrations.
     */
    @method({ name: 'domainName', type: ABIDataTypes.STRING })
    @emit('DomainRegistered')
    public completeRegistration(calldata: Calldata): BytesWriter {
        this.requireEOA();

        const domainName = calldata.readStringWithLength();
        const domainKey = this.getDomainKeyU256(domainName);
        const blockNumber = Blockchain.block.number;

        // Verify reservation exists and is valid
        const reservationBlock = this.domainReservationBlock.get(domainKey).toU64();
        if (reservationBlock == 0) {
            throw new Revert('No reservation found');
        }

        // Must be at least 1 block after reservation
        if (blockNumber <= reservationBlock) {
            throw new Revert('Must wait at least 1 block');
        }

        // Must be within timeout
        const reservationExpiry = SafeMath.add64(reservationBlock, RESERVATION_TIMEOUT_BLOCKS);
        if (blockNumber > reservationExpiry) {
            throw new Revert('Reservation expired');
        }

        // Must be the reserver
        const reserver = this._u256ToAddress(this.domainReservationOwner.get(domainKey));
        if (!Blockchain.tx.sender.equals(reserver)) {
            throw new Revert('Not reservation owner');
        }

        const years = this.domainReservationYears.get(domainKey).toU64();

        // Re-verify domain availability (could have changed via upgrade, etc.)
        const exists = !this.domainExists.get(domainKey).isZero();
        if (exists) {
            const expiry = this.domainExpiry.get(domainKey).toU64();
            const graceEnd = SafeMath.add64(expiry, GRACE_PERIOD_BLOCKS);
            if (blockNumber <= graceEnd) {
                throw new Revert('Domain is not available');
            }
            this.domainPendingOwner.set(domainKey, u256.Zero);
            this.domainPendingTimestamp.set(domainKey, u256.Zero);
            this._removeDomainFromOwner(this.domainOwner.get(domainKey), domainKey);
        }

        const basePrice = this.domainPriceSats.get(u256.Zero).toU64();
        const auctionPrice = this.calculateAuctionPrice(domainName, domainKey, blockNumber);

        let totalPrice: u64;
        if (auctionPrice > basePrice) {
            const renewalPerYear = this.getPremiumRenewalSats(auctionPrice);
            totalPrice = SafeMath.add64(auctionPrice, SafeMath.mul64(renewalPerYear, years));
        } else {
            totalPrice = SafeMath.mul64(basePrice, years);
        }
        const remainingPrice =
            totalPrice > RESERVATION_FEE_SATS
                ? SafeMath.sub64(totalPrice, RESERVATION_FEE_SATS)
                : <u64>0;

        if (remainingPrice > 0) {
            this.verifyPayment(remainingPrice);
        }

        // Register domain
        const sender = Blockchain.tx.sender;
        const senderU256 = this._addressToU256(sender);
        const expiryBlock = SafeMath.add64(blockNumber, SafeMath.mul64(BLOCKS_PER_YEAR, years));

        this.domainExists.set(domainKey, u256.One);
        this.domainOwner.set(domainKey, senderU256);
        this.domainCreated.set(domainKey, u256.fromU64(blockNumber));
        this.domainTTL.set(domainKey, u256.fromU64(DEFAULT_TTL));
        this.domainExpiry.set(domainKey, u256.fromU64(expiryBlock));
        this.domainAuctionStart.set(domainKey, u256.Zero);

        this.contenthashType.set(domainKey, u256.Zero);
        this.contenthashData.set(domainKey, u256.Zero);
        this.domainGeneration.set(
            domainKey,
            SafeMath.add(this.domainGeneration.get(domainKey), u256.One),
        );
        this.domainPaidPriceSats.set(domainKey, u256.fromU64(auctionPrice));
        this.domainPaidPriceMoto.set(domainKey, u256.Zero);

        this._addDomainToOwner(senderU256, domainKey);

        // Clear reservation
        this.domainReservationOwner.set(domainKey, u256.Zero);
        this.domainReservationBlock.set(domainKey, u256.Zero);
        this.domainReservationYears.set(domainKey, u256.Zero);

        this.emitEvent(new DomainRegisteredEvent(domainKey, sender, blockNumber));

        return new BytesWriter(0);
    }

    /**
     * Renew an existing domain subscription.
     * Can be called by the domain owner during active period or grace period.
     * Always charges base price per year (no premium surcharge on renewals).
     * @param calldata Contains domain name and years to extend (1-10)
     */
    @method(
        { name: 'domainName', type: ABIDataTypes.STRING },
        { name: 'years', type: ABIDataTypes.UINT64 },
    )
    @emit('DomainRenewed')
    public renewDomain(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const years = calldata.readU64();

        if (years < 1 || years > MAX_REGISTRATION_YEARS) {
            throw new Revert('Years must be 1-10');
        }

        const domainKey = this.getDomainKeyU256(domainName);
        const blockNumber = Blockchain.block.number;

        // Domain must exist
        if (this.domainExists.get(domainKey).isZero()) {
            throw new Revert('Domain does not exist');
        }

        // Must be the domain owner
        const owner = this._u256ToAddress(this.domainOwner.get(domainKey));
        if (!Blockchain.tx.sender.equals(owner)) {
            throw new Revert('Not domain owner');
        }

        // Must be within active period or grace period (not fully expired)
        const currentExpiry = this.domainExpiry.get(domainKey).toU64();
        const graceEnd = SafeMath.add64(currentExpiry, GRACE_PERIOD_BLOCKS);
        if (blockNumber > graceEnd) {
            throw new Revert('Domain expired past grace period');
        }

        const basePrice = this.domainPriceSats.get(u256.Zero).toU64();
        const paidPrice = this.domainPaidPriceSats.get(domainKey).toU64();

        let totalPrice: u64;
        if (paidPrice > basePrice) {
            totalPrice = SafeMath.mul64(this.getPremiumRenewalSats(paidPrice), years);
        } else {
            totalPrice = SafeMath.mul64(basePrice, years);
        }
        this.verifyPayment(totalPrice);

        // Extend expiry from max(currentBlock, currentExpiry)
        // - Before expiry: extends from current expiry (don't lose remaining time)
        // - During grace: extends from current block (grace time is lost)
        const extensionBase = blockNumber > currentExpiry ? blockNumber : currentExpiry;
        const newExpiry = SafeMath.add64(extensionBase, SafeMath.mul64(BLOCKS_PER_YEAR, years));
        this.domainExpiry.set(domainKey, u256.fromU64(newExpiry));

        this.emitEvent(new DomainRenewedEvent(domainKey, owner, newExpiry, blockNumber));

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

        // Verify caller is owner and domain is fully active (not in grace)
        this.requireActiveDomainOwner(domainKey);

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

        // Verify domain exists
        if (this.domainExists.get(domainKey).isZero()) {
            throw new Revert('Domain does not exist');
        }

        // Verify domain is fully active (not in grace — transfers only on active domains)
        const expiry = this.domainExpiry.get(domainKey).toU64();
        if (Blockchain.block.number > expiry) {
            throw new Revert('Domain not active');
        }

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
        const previousOwnerU256 = this.domainOwner.get(domainKey);
        const previousOwner = this._u256ToAddress(previousOwnerU256);
        const pendingOwnerU256 = this._addressToU256(pendingOwner);
        const blockNumber = Blockchain.block.number;

        this.domainOwner.set(domainKey, pendingOwnerU256);
        this.domainPendingOwner.set(domainKey, u256.Zero);
        this.domainPendingTimestamp.set(domainKey, u256.Zero);

        this._removeDomainFromOwner(previousOwnerU256, domainKey);
        this._addDomainToOwner(pendingOwnerU256, domainKey);

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

        // Verify caller is owner and domain is fully active (not in grace)
        this.requireActiveDomainOwner(domainKey);

        // Validate new owner
        if (newOwner.equals(Address.zero())) {
            throw new Revert('Invalid new owner');
        }

        // Cannot transfer to self
        if (newOwner.equals(Blockchain.tx.sender)) {
            throw new Revert('Cannot transfer to self');
        }

        // Get current owner for event
        const previousOwnerU256 = this.domainOwner.get(domainKey);
        const previousOwner = this._u256ToAddress(previousOwnerU256);
        const newOwnerU256 = this._addressToU256(newOwner);
        const blockNumber = Blockchain.block.number;

        // Clear any pending transfer
        this.domainPendingOwner.set(domainKey, u256.Zero);
        this.domainPendingTimestamp.set(domainKey, u256.Zero);

        // Transfer ownership
        this.domainOwner.set(domainKey, newOwnerU256);

        this._removeDomainFromOwner(previousOwnerU256, domainKey);
        this._addDomainToOwner(newOwnerU256, domainKey);

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

        // Accept both Schnorr (64 bytes) and ML-DSA signatures
        if (signature.length < 64) {
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

        // Verify domain is fully active (not in grace period — no transfers on expiring domains)
        const expiry = this.domainExpiry.get(domainKey).toU64();
        if (Blockchain.block.number > expiry) {
            throw new Revert('Domain not active');
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

        // Get current nonce for replay protection
        const nonce = this.domainNonce.get(domainKey);

        const methodId = Uint8Array.wrap(String.UTF8.encode('transferDomain'));
        const messageData = new BytesWriter(
            methodId.length +
                ADDRESS_BYTE_LENGTH +
                U256_BYTE_LENGTH +
                ADDRESS_BYTE_LENGTH +
                U64_BYTE_LENGTH +
                U256_BYTE_LENGTH,
        );
        messageData.writeBytes(methodId);
        messageData.writeAddress(Blockchain.contractAddress);
        messageData.writeU256(domainKey);
        messageData.writeAddress(newOwner);
        messageData.writeU64(deadline);
        messageData.writeU256(nonce);

        const messageHash = Blockchain.sha256(messageData.getBuffer());

        // Verify signature
        if (!Blockchain.verifySignature(owner, signature, messageHash)) {
            throw new Revert('Invalid signature');
        }

        // Increment nonce to prevent replay
        this.domainNonce.set(domainKey, SafeMath.add(nonce, u256.One));

        const blockNumber = Blockchain.block.number;

        // Clear any pending transfer
        this.domainPendingOwner.set(domainKey, u256.Zero);
        this.domainPendingTimestamp.set(domainKey, u256.Zero);

        // Transfer ownership
        const storedOwnerU256 = this._addressToU256(storedOwner);
        const newOwnerU256 = this._addressToU256(newOwner);
        this.domainOwner.set(domainKey, newOwnerU256);

        this._removeDomainFromOwner(storedOwnerU256, domainKey);
        this._addDomainToOwner(newOwnerU256, domainKey);

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

        if (!this.subdomainExists.get(subdomainKey).isZero()) {
            const currentGen = this.domainGeneration.get(parentKey);
            const subGen = this.subdomainGeneration.get(subdomainKey);
            if (currentGen == subGen) {
                throw new Revert('Subdomain already exists');
            }
        }

        // Determine owner (default to caller if zero address)
        const owner = subdomainOwner.equals(Address.zero()) ? Blockchain.tx.sender : subdomainOwner;

        const blockNumber = Blockchain.block.number;

        // Register subdomain
        this.subdomainExists.set(subdomainKey, u256.One);
        this.subdomainOwner.set(subdomainKey, this._addressToU256(owner));
        this.subdomainParent.set(subdomainKey, parentKey);
        this.subdomainTTL.set(subdomainKey, u256.fromU64(DEFAULT_TTL));
        this.subdomainGeneration.set(subdomainKey, this.domainGeneration.get(parentKey));

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
     * Get domain information including subscription status.
     */
    @method({ name: 'domainName', type: ABIDataTypes.STRING })
    @returns(
        { name: 'exists', type: ABIDataTypes.BOOL },
        { name: 'owner', type: ABIDataTypes.ADDRESS },
        { name: 'createdAt', type: ABIDataTypes.UINT64 },
        { name: 'expiresAt', type: ABIDataTypes.UINT64 },
        { name: 'ttl', type: ABIDataTypes.UINT64 },
        { name: 'isActive', type: ABIDataTypes.BOOL },
        { name: 'inGracePeriod', type: ABIDataTypes.BOOL },
    )
    public getDomain(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const domainKey = this.getDomainKeyU256(domainName);
        const blockNumber = Blockchain.block.number;

        const exists = !this.domainExists.get(domainKey).isZero();
        const owner = exists
            ? this._u256ToAddress(this.domainOwner.get(domainKey))
            : Address.zero();
        const createdAt = exists ? this.domainCreated.get(domainKey).toU64() : <u64>0;
        const expiresAt = exists ? this.domainExpiry.get(domainKey).toU64() : <u64>0;
        const ttl = exists ? this.domainTTL.get(domainKey).toU64() : <u64>0;

        // Active = not expired yet
        const isActive = exists && blockNumber <= expiresAt;
        // In grace = expired but within grace window
        const inGracePeriod =
            exists && !isActive && blockNumber <= SafeMath.add64(expiresAt, GRACE_PERIOD_BLOCKS);

        const response = new BytesWriter(1 + 32 + 8 + 8 + 8 + 1 + 1);
        response.writeBoolean(exists);
        response.writeAddress(owner);
        response.writeU64(createdAt);
        response.writeU64(expiresAt);
        response.writeU64(ttl);
        response.writeBoolean(isActive);
        response.writeBoolean(inGracePeriod);

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
     * Returns zero address for expired domains (past grace period).
     */
    @method({ name: 'name', type: ABIDataTypes.STRING })
    @returns({ name: 'owner', type: ABIDataTypes.ADDRESS })
    public resolve(calldata: Calldata): BytesWriter {
        const name = calldata.readStringWithLength();
        const nameKey = this.resolveNameKey(name);
        const blockNumber = Blockchain.block.number;

        let owner: Address;
        if (this.isSubdomain(name)) {
            if (this.subdomainExists.get(nameKey).isZero()) {
                owner = Address.zero();
            } else {
                const parentName = this.getParentDomain(name);
                const parentKey = this.getDomainKeyU256(parentName);
                const parentExpiry = this.domainExpiry.get(parentKey).toU64();
                const parentGraceEnd = SafeMath.add64(parentExpiry, GRACE_PERIOD_BLOCKS);
                const currentGen = this.domainGeneration.get(parentKey);
                const subGen = this.subdomainGeneration.get(nameKey);
                if (blockNumber > parentGraceEnd || currentGen != subGen) {
                    owner = Address.zero();
                } else {
                    owner = this._u256ToAddress(this.subdomainOwner.get(nameKey));
                }
            }
        } else {
            if (this.domainExists.get(nameKey).isZero()) {
                owner = Address.zero();
            } else {
                // Check if domain is still within active + grace period
                const expiry = this.domainExpiry.get(nameKey).toU64();
                const graceEnd = SafeMath.add64(expiry, GRACE_PERIOD_BLOCKS);
                if (blockNumber > graceEnd) {
                    owner = Address.zero();
                } else {
                    owner = this._u256ToAddress(this.domainOwner.get(nameKey));
                }
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
     * Get current domain registration price for a specific domain and year count.
     * Returns the total cost including Dutch auction premium (if applicable) + base rate for extra years.
     */
    @method(
        { name: 'domainName', type: ABIDataTypes.STRING },
        { name: 'years', type: ABIDataTypes.UINT64 },
    )
    @returns(
        { name: 'totalPriceSats', type: ABIDataTypes.UINT64 },
        { name: 'auctionPriceSats', type: ABIDataTypes.UINT64 },
        { name: 'renewalPerYear', type: ABIDataTypes.UINT64 },
    )
    public getDomainPrice(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const years = calldata.readU64();

        if (years < 1 || years > MAX_REGISTRATION_YEARS) {
            throw new Revert('Years must be 1-10');
        }

        const domainKey = this.getDomainKeyU256(domainName);
        const blockNumber = Blockchain.block.number;
        const basePrice = this.domainPriceSats.get(u256.Zero).toU64();
        const auctionPrice = this.calculateAuctionPrice(domainName, domainKey, blockNumber);

        let totalPrice: u64;
        let renewalPerYear: u64;
        if (auctionPrice > basePrice) {
            renewalPerYear = this.getPremiumRenewalSats(auctionPrice);
            totalPrice = SafeMath.add64(auctionPrice, SafeMath.mul64(renewalPerYear, years));
        } else {
            renewalPerYear = basePrice;
            totalPrice = SafeMath.mul64(basePrice, years);
        }

        const response = new BytesWriter(8 + 8 + 8);
        response.writeU64(totalPrice);
        response.writeU64(auctionPrice);
        response.writeU64(renewalPerYear);

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

    /**
     * Get the current nonce for a domain (used in signature-based transfers).
     */
    @method({ name: 'domainName', type: ABIDataTypes.STRING })
    @returns({ name: 'nonce', type: ABIDataTypes.UINT256 })
    public getDomainNonce(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const domainKey = this.getDomainKeyU256(domainName);

        const response = new BytesWriter(32);
        response.writeU256(this.domainNonce.get(domainKey));
        return response;
    }

    /**
     * Get reservation info for a domain.
     */
    @method({ name: 'domainName', type: ABIDataTypes.STRING })
    @returns(
        { name: 'reserver', type: ABIDataTypes.ADDRESS },
        { name: 'reservedAt', type: ABIDataTypes.UINT64 },
        { name: 'years', type: ABIDataTypes.UINT64 },
        { name: 'isActive', type: ABIDataTypes.BOOL },
    )
    public getReservation(calldata: Calldata): BytesWriter {
        const domainName = calldata.readStringWithLength();
        const domainKey = this.getDomainKeyU256(domainName);
        const blockNumber = Blockchain.block.number;

        const reserver = this._u256ToAddress(this.domainReservationOwner.get(domainKey));
        const reservedAt = this.domainReservationBlock.get(domainKey).toU64();
        const years = this.domainReservationYears.get(domainKey).toU64();
        const isActive =
            reservedAt > 0 && blockNumber <= SafeMath.add64(reservedAt, RESERVATION_TIMEOUT_BLOCKS);

        const response = new BytesWriter(32 + 8 + 8 + 1);
        response.writeAddress(reserver);
        response.writeU64(reservedAt);
        response.writeU64(years);
        response.writeBoolean(isActive);
        return response;
    }

    /**
     * Get all domain keys owned by an address (paginated).
     * Returns total count and a page of domain keys.
     */
    @method(
        { name: 'owner', type: ABIDataTypes.ADDRESS },
        { name: 'offset', type: ABIDataTypes.UINT64 },
        { name: 'limit', type: ABIDataTypes.UINT64 },
    )
    @returns(
        { name: 'total', type: ABIDataTypes.UINT64 },
        { name: 'keys', type: ABIDataTypes.ARRAY_OF_BYTES },
    )
    public getDomainsByOwner(calldata: Calldata): BytesWriter {
        const owner = calldata.readAddress();
        const offset = calldata.readU64();
        let limit = calldata.readU64();

        if (limit > 50) limit = 50;

        const ownerU256 = this._addressToU256(owner);
        const total = this.ownerDomainCount.get(ownerU256).toU64();

        if (offset >= total || limit == 0) {
            const response = new BytesWriter(10);
            response.writeU64(total);
            response.writeU16(0);
            return response;
        }

        const remaining = total - offset;
        const count: u16 = <u16>(remaining < limit ? remaining : limit);

        const response = new BytesWriter(8 + 2 + <i32>count * 36);
        response.writeU64(total);
        response.writeU16(count);

        for (let i: u16 = 0; i < count; i++) {
            const compositeKey = this._ownerIndexKey(ownerU256, offset + <u64>i);
            const value = this.ownerDomainAtIndex.get(compositeKey);
            response.writeBytesWithLength(value.toUint8Array());
        }

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

    private _ownerIndexKey(ownerU256: u256, index: u64): u256 {
        const writer = new BytesWriter(40);
        writer.writeU256(ownerU256);
        writer.writeU64(index);
        return u256.fromUint8ArrayBE(Blockchain.sha256(writer.getBuffer()));
    }

    private _addDomainToOwner(ownerU256: u256, domainKey: u256): void {
        // Guard against double-insertion
        if (!this.domainIndexInOwnerList.get(domainKey).isZero()) return;

        const count = this.ownerDomainCount.get(ownerU256).toU64();
        const compositeKey = this._ownerIndexKey(ownerU256, count);
        this.ownerDomainAtIndex.set(compositeKey, domainKey);
        this.domainIndexInOwnerList.set(domainKey, u256.fromU64(count + 1)); // 1-based (0 = not indexed)
        this.ownerDomainCount.set(ownerU256, u256.fromU64(count + 1));
    }

    private _removeDomainFromOwner(ownerU256: u256, domainKey: u256): void {
        const indexPlusOne = this.domainIndexInOwnerList.get(domainKey).toU64();
        if (indexPlusOne == 0) return; // Not indexed (pre-upgrade domain)

        const idx = indexPlusOne - 1;
        const count = this.ownerDomainCount.get(ownerU256).toU64();
        if (count == 0) return;

        const lastIdx = count - 1;
        const lastCompositeKey = this._ownerIndexKey(ownerU256, lastIdx);

        if (idx != lastIdx) {
            // Swap with last element
            const lastDomainKey = this.ownerDomainAtIndex.get(lastCompositeKey);
            const idxCompositeKey = this._ownerIndexKey(ownerU256, idx);
            this.ownerDomainAtIndex.set(idxCompositeKey, lastDomainKey);
            this.domainIndexInOwnerList.set(lastDomainKey, u256.fromU64(idx + 1));
        }

        this.ownerDomainAtIndex.set(lastCompositeKey, u256.Zero);
        this.domainIndexInOwnerList.set(domainKey, u256.Zero);
        this.ownerDomainCount.set(ownerU256, u256.fromU64(lastIdx));
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

    private isValidDomainName(domain: string): boolean {
        const len = domain.length;
        if (len < <i32>MIN_DOMAIN_LENGTH || len > <i32>MAX_DOMAIN_LENGTH) return false;
        if (!this.isAlphanumeric(domain.charCodeAt(0))) return false;
        if (!this.isAlphanumeric(domain.charCodeAt(len - 1))) return false;
        for (let i = 0; i < len; i++) {
            const c = domain.charCodeAt(i);
            if (!((c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c == 45))
                return false;
        }
        for (let i = 0; i < len - 1; i++) {
            if (domain.charCodeAt(i) == 45 && domain.charCodeAt(i + 1) == 45) return false;
        }
        return true;
    }

    private validateDomainName(domain: string): void {
        const len = domain.length;
        if (len < <i32>MIN_DOMAIN_LENGTH || len > <i32>MAX_DOMAIN_LENGTH) {
            throw new Revert('Domain must be 1-63 characters');
        }

        const first = domain.charCodeAt(0);
        if (!this.isAlphanumeric(first)) {
            throw new Revert('Domain must start with alphanumeric');
        }

        const last = domain.charCodeAt(len - 1);
        if (!this.isAlphanumeric(last)) {
            throw new Revert('Domain must end with alphanumeric');
        }

        for (let i = 0; i < len; i++) {
            const c = domain.charCodeAt(i);
            const isLower = c >= 97 && c <= 122;
            const isUpper = c >= 65 && c <= 90;
            const isDigit = c >= 48 && c <= 57;
            const isHyphen = c == 45;

            if (!isLower && !isUpper && !isDigit && !isHyphen) {
                throw new Revert('Invalid character in domain');
            }
        }

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

        const first = label.charCodeAt(0);
        if (!this.isAlphanumeric(first)) {
            throw new Revert('Subdomain must start with alphanumeric');
        }

        const last = label.charCodeAt(len - 1);
        if (!this.isAlphanumeric(last)) {
            throw new Revert('Subdomain must end with alphanumeric');
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

        // No consecutive hyphens
        for (let i = 0; i < len - 1; i++) {
            if (label.charCodeAt(i) == 45 && label.charCodeAt(i + 1) == 45) {
                throw new Revert('No consecutive hyphens allowed');
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

    /**
     * Get the static premium tier price for a domain (before Dutch auction decay).
     * Returns the base price if the domain is not premium.
     */
    private getPremiumTierPrice(domainName: string): u64 {
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
            return PREMIUM_TIER_5_PRICE_SATS;
        }

        if (this.isInPremiumList(lowerName, PREMIUM_TIER_6_DOMAINS)) {
            return PREMIUM_TIER_5_PRICE_SATS;
        }

        if (len == 5) {
            return PREMIUM_TIER_5_PRICE_SATS;
        }

        return basePrice;
    }

    /**
     * Calculate the current Dutch auction price for a domain.
     * Premium domains start at tier price and linearly decay to base price over AUCTION_DURATION_BLOCKS.
     * Non-premium domains always return the base price.
     *
     * Auction start is determined by:
     * - For never-registered domains: contract deployment block
     * - For expired domains (re-registration): expiry + GRACE_PERIOD (when domain became public)
     */
    private calculateAuctionPrice(domainName: string, domainKey: u256, currentBlock: u64): u64 {
        const basePrice = this.domainPriceSats.get(u256.Zero).toU64();
        const premiumPrice = this.getPremiumTierPrice(domainName);

        // Non-premium domains: no auction, just base price
        if (premiumPrice <= basePrice) {
            return basePrice;
        }

        // Auction floor is the immutable default price, not the mutable base price.
        // This prevents the deployer from manipulating active auctions.
        const auctionFloor: u64 = DEFAULT_DOMAIN_PRICE_SATS;

        // Determine auction start block
        const auctionStart = this.getAuctionStart(domainKey);

        // If current block is before auction start (shouldn't happen normally), use full premium
        if (currentBlock <= auctionStart) {
            return premiumPrice;
        }

        // Calculate linear decay: price decreases from premiumPrice to auctionFloor
        const elapsed = currentBlock - auctionStart;

        // If past auction duration, price has decayed to floor
        if (elapsed >= AUCTION_DURATION_BLOCKS) {
            return auctionFloor;
        }

        // Linear interpolation: price = premiumPrice - (elapsed * (premiumPrice - auctionFloor)) / AUCTION_DURATION_BLOCKS
        const priceDelta = premiumPrice - auctionFloor;
        const decay = SafeMath.div64(SafeMath.mul64(elapsed, priceDelta), AUCTION_DURATION_BLOCKS);

        return premiumPrice - decay;
    }

    /**
     * Extract the parent domain name from a subdomain (e.g., "sub.example" -> "example").
     */
    private getParentDomain(fullName: string): string {
        for (let i: i32 = 0; i < fullName.length; i++) {
            if (fullName.charCodeAt(i) == 46) {
                // '.'
                return fullName.substring(i + 1);
            }
        }
        return fullName;
    }

    /**
     * Get the auction start block for a domain (read-only, no storage writes).
     * - If domainAuctionStart is set: use it
     * - If domain existed before: expiry + grace period
     * - Otherwise: deployment block
     */
    /** Returns max(price * 10%, PREMIUM_RENEWAL_MIN_SATS) */
    private getPremiumRenewalSats(price: u64): u64 {
        const tenPercent = SafeMath.div64(price, 10);
        return tenPercent > PREMIUM_RENEWAL_MIN_SATS ? tenPercent : PREMIUM_RENEWAL_MIN_SATS;
    }

    private getAuctionStart(domainKey: u256): u64 {
        const storedAuctionStart = this.domainAuctionStart.get(domainKey).toU64();
        if (storedAuctionStart > 0) {
            return storedAuctionStart;
        }

        const existsVal = this.domainExists.get(domainKey);
        if (!existsVal.isZero()) {
            const expiry = this.domainExpiry.get(domainKey).toU64();
            return SafeMath.add64(expiry, GRACE_PERIOD_BLOCKS);
        }

        return this.deploymentBlock.get(u256.Zero).toU64();
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

        // Check that domain is still active (not expired past grace period)
        const expiry = this.domainExpiry.get(domainKey).toU64();
        const graceEnd = SafeMath.add64(expiry, GRACE_PERIOD_BLOCKS);
        if (Blockchain.block.number > graceEnd) {
            throw new Revert('Domain expired');
        }

        const owner = this._u256ToAddress(this.domainOwner.get(domainKey));
        if (!Blockchain.tx.sender.equals(owner)) {
            throw new Revert('Not domain owner');
        }
    }

    /**
     * Stricter ownership check: domain must be fully active (not in grace period).
     * Used for transfers to prevent moving expired domains at base renewal cost.
     */
    private requireActiveDomainOwner(domainKey: u256): void {
        if (this.domainExists.get(domainKey).isZero()) {
            throw new Revert('Domain does not exist');
        }

        const expiry = this.domainExpiry.get(domainKey).toU64();
        if (Blockchain.block.number > expiry) {
            throw new Revert('Domain not active');
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
            const parentName = this.getParentDomain(name);
            const parentKey = this.getDomainKeyU256(parentName);
            const parentExpiry = this.domainExpiry.get(parentKey).toU64();
            const parentGraceEnd = SafeMath.add64(parentExpiry, GRACE_PERIOD_BLOCKS);
            if (Blockchain.block.number > parentGraceEnd) {
                throw new Revert('Parent domain expired');
            }
            const currentGen = this.domainGeneration.get(parentKey);
            const subGen = this.subdomainGeneration.get(nameKey);
            if (currentGen != subGen) {
                throw new Revert('Subdomain invalidated by re-registration');
            }
            const owner = this._u256ToAddress(this.subdomainOwner.get(nameKey));
            if (!Blockchain.tx.sender.equals(owner)) {
                throw new Revert('Not subdomain owner');
            }
        } else {
            this.requireDomainOwner(nameKey);
        }
    }

    private requireEOA(): void {
        if (!Blockchain.tx.origin.equals(Blockchain.tx.sender)) {
            throw new Revert('Contracts not allowed');
        }
        if (Blockchain.isContract(Blockchain.tx.sender)) {
            throw new Revert('Sender must be EOA');
        }
    }

    private verifyReservationFee(): void {
        let totalPaid: u64 = 0;

        const outputs = Blockchain.tx.outputs;
        for (let i: i32 = 0; i < outputs.length; i++) {
            if (outputs[i].to == RESERVATION_FEE_ADDRESS) {
                totalPaid = SafeMath.add64(totalPaid, outputs[i].value);
            }
        }

        if (totalPaid < RESERVATION_FEE_SATS) {
            throw new Revert('Insufficient reservation fee');
        }
    }

    private requireMotoEnabled(): void {
        if (this.motoEnabled.get(u256.Zero).isZero()) {
            throw new Revert('MOTO payments are disabled');
        }
    }

    // =========================================================================
    // MOTO PAYMENT HELPERS
    // =========================================================================

    /**
     * Get the premium tier index for a domain (0-5), or 255 for non-premium.
     */
    private getDomainTierIndex(domainName: string): u8 {
        const lowerName = this.toLowerCase(domainName);
        const len = lowerName.length;

        if (this.isInPremiumList(lowerName, PREMIUM_TIER_0_DOMAINS)) return 0;
        if (len == 1) return 1;
        if (len == 2) return 2;
        if (this.isInPremiumList(lowerName, PREMIUM_TIER_1_DOMAINS)) return 1;
        if (this.isInPremiumList(lowerName, PREMIUM_TIER_2_DOMAINS)) return 2;
        if (len == 3) return 3;
        if (this.isInPremiumList(lowerName, PREMIUM_TIER_3_DOMAINS)) return 3;
        if (len == 4) return 4;
        if (this.isInPremiumList(lowerName, PREMIUM_TIER_4_DOMAINS)) return 4;
        if (this.isInPremiumList(lowerName, PREMIUM_TIER_5_DOMAINS)) return 5;
        if (this.isInPremiumList(lowerName, PREMIUM_TIER_6_DOMAINS)) return 5;
        if (len == 5) return 5;

        return 255;
    }

    /**
     * Calculate total MOTO cost for domain registration.
     * Premium tier MOTO price (with Dutch auction decay) + base MOTO price for extra years.
     */
    /** Returns the first-year MOTO price (auction or base) for a domain. */
    private getMotoFirstYearPrice(
        domainName: string,
        domainKey: u256,
        currentBlock: u64,
        motoBase: u256,
    ): u256 {
        const tierIndex = this.getDomainTierIndex(domainName);
        if (tierIndex == 255) {
            return motoBase;
        }
        const motoTierPrice = this.motoTierPrices.get(u256.fromU32(<u32>tierIndex));
        if (motoTierPrice.isZero()) {
            throw new Revert('MOTO tier price not set');
        }
        return this.calculateMotoAuctionPrice(motoTierPrice, motoBase, domainKey, currentBlock);
    }

    /**
     * Dutch auction decay for MOTO prices: linearly decays from tierPrice to basePrice.
     */
    private calculateMotoAuctionPrice(
        tierPrice: u256,
        basePrice: u256,
        domainKey: u256,
        currentBlock: u64,
    ): u256 {
        if (tierPrice <= basePrice) {
            return basePrice;
        }

        const auctionStart = this.getAuctionStart(domainKey);

        if (currentBlock <= auctionStart) {
            return tierPrice;
        }

        const elapsed = currentBlock - auctionStart;
        if (elapsed >= AUCTION_DURATION_BLOCKS) {
            return basePrice;
        }

        const priceDelta = SafeMath.sub(tierPrice, basePrice);
        const decay = SafeMath.div(
            SafeMath.mul(priceDelta, u256.fromU64(elapsed)),
            u256.fromU64(AUCTION_DURATION_BLOCKS),
        );

        return SafeMath.sub(tierPrice, decay);
    }

    /**
     * Collect MOTO payment from sender via transferFrom.
     */
    private collectMotoPayment(amount: u256): void {
        const motoAddr = this._u256ToAddress(this.motoTokenAddress.get(u256.Zero));
        if (motoAddr.equals(Address.zero())) {
            throw new Revert('MOTO token address not set');
        }

        TransferHelper.transferFrom(
            motoAddr,
            Blockchain.tx.sender,
            Blockchain.contractAddress,
            amount,
        );
    }
}
