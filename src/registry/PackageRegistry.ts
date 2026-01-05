/**
 * OPNet Package Registry Smart Contract
 *
 * A decentralized package registry for OPNet plugins. Manages:
 * - Package ownership (tied to MLDSA public key hash)
 * - Scoped packages (@scope/package-name)
 * - Version metadata with IPFS storage
 * - 72-hour mutability window for deprecation
 * - Two-step ownership transfers
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    Blockchain,
    BytesWriter,
    Calldata,
    OP_NET,
    Revert,
    SafeMath,
    StoredString,
} from '@btc-vision/btc-runtime/runtime';
import { StoredMapU256 } from '@btc-vision/btc-runtime/runtime/storage/maps/StoredMapU256';
import { AdvancedStoredString } from '@btc-vision/btc-runtime/runtime/storage/AdvancedStoredString';

import {
    PackagePriceChangedEvent,
    PackageRegisteredEvent,
    PackageTransferCancelledEvent,
    PackageTransferCompletedEvent,
    PackageTransferInitiatedEvent,
    ScopePriceChangedEvent,
    ScopeRegisteredEvent,
    ScopeTransferCancelledEvent,
    ScopeTransferCompletedEvent,
    ScopeTransferInitiatedEvent,
    TreasuryAddressChangedEvent,
    VersionDeprecatedEvent,
    VersionPublishedEvent,
    VersionUndeprecatedEvent,
} from './events/RegistryEvents';

import {
    MLDSA44_SIGNATURE_LEN,
    MLDSA65_SIGNATURE_LEN,
    MLDSA87_SIGNATURE_LEN,
} from '@btc-vision/btc-runtime/runtime/env/consensus/MLDSAMetadata';

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
    RESERVED_SCOPE,
} from './constants';

// =============================================================================
// Storage Pointer Allocation (Module Level - CRITICAL)
// =============================================================================

// Contract-level settings
const treasuryAddressPointer: u16 = Blockchain.nextPointer;
const scopePriceSatsPointer: u16 = Blockchain.nextPointer;
const packagePriceSatsPointer: u16 = Blockchain.nextPointer;

// Scope storage
const scopeExistsPointer: u16 = Blockchain.nextPointer;
const scopeOwnerPointer: u16 = Blockchain.nextPointer;
const scopeCreatedPointer: u16 = Blockchain.nextPointer;

// Scope transfer tracking
const scopePendingOwnerPointer: u16 = Blockchain.nextPointer;
const scopePendingTimestampPointer: u16 = Blockchain.nextPointer;

// Package-level storage
const packageExistsPointer: u16 = Blockchain.nextPointer;
const packageOwnerPointer: u16 = Blockchain.nextPointer;
const packageCreatedPointer: u16 = Blockchain.nextPointer;
const packageVersionCountPointer: u16 = Blockchain.nextPointer;
const packageLatestVersionPointer: u16 = Blockchain.nextPointer;

// Package transfer tracking
const pkgPendingOwnerPointer: u16 = Blockchain.nextPointer;
const pkgPendingTimestampPointer: u16 = Blockchain.nextPointer;

// Version-level storage
const versionExistsPointer: u16 = Blockchain.nextPointer;
const versionIpfsCidPointer: u16 = Blockchain.nextPointer;
const versionChecksumPointer: u16 = Blockchain.nextPointer;
const versionSigHashPointer: u16 = Blockchain.nextPointer;
const versionMldsaLevelPointer: u16 = Blockchain.nextPointer;
const versionOpnetRangePointer: u16 = Blockchain.nextPointer;
const versionPluginTypePointer: u16 = Blockchain.nextPointer;
const versionPermHashPointer: u16 = Blockchain.nextPointer;
const versionDepsHashPointer: u16 = Blockchain.nextPointer;
const versionPublisherPointer: u16 = Blockchain.nextPointer;
const versionTimestampPointer: u16 = Blockchain.nextPointer;
const versionDeprecatedPointer: u16 = Blockchain.nextPointer;
const versionDepReasonPointer: u16 = Blockchain.nextPointer;

// =============================================================================
// Contract Implementation
// =============================================================================

@final
export class PackageRegistry extends OP_NET {
    // -------------------------------------------------------------------------
    // Settings Storage
    // -------------------------------------------------------------------------
    private readonly treasuryAddress: StoredString;
    private readonly scopePriceSats: StoredMapU256; // Use map with key 0
    private readonly packagePriceSats: StoredMapU256; // Use map with key 0

    // -------------------------------------------------------------------------
    // Scope Storage Maps
    // -------------------------------------------------------------------------
    private readonly scopeExists: StoredMapU256;
    private readonly scopeOwner: StoredMapU256;
    private readonly scopeCreated: StoredMapU256;
    private readonly scopePendingOwner: StoredMapU256;
    private readonly scopePendingTimestamp: StoredMapU256;

    // -------------------------------------------------------------------------
    // Package Storage Maps
    // -------------------------------------------------------------------------
    private readonly packageExists: StoredMapU256;
    private readonly packageOwner: StoredMapU256;
    private readonly packageCreated: StoredMapU256;
    private readonly packageVersionCount: StoredMapU256;

    // Package transfer tracking
    private readonly pkgPendingOwner: StoredMapU256;
    private readonly pkgPendingTimestamp: StoredMapU256;

    // -------------------------------------------------------------------------
    // Version Storage Maps
    // -------------------------------------------------------------------------
    private readonly versionExists: StoredMapU256;
    private readonly versionChecksum: StoredMapU256;
    private readonly versionSigHash: StoredMapU256;
    private readonly versionMldsaLevel: StoredMapU256;
    private readonly versionPluginType: StoredMapU256;
    private readonly versionPermHash: StoredMapU256;
    private readonly versionDepsHash: StoredMapU256;
    private readonly versionPublisher: StoredMapU256;
    private readonly versionTimestamp: StoredMapU256;
    private readonly versionDeprecated: StoredMapU256;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    public constructor() {
        super();

        // Initialize settings storage
        this.treasuryAddress = new StoredString(treasuryAddressPointer);
        this.scopePriceSats = new StoredMapU256(scopePriceSatsPointer);
        this.packagePriceSats = new StoredMapU256(packagePriceSatsPointer);

        // Initialize scope storage
        this.scopeExists = new StoredMapU256(scopeExistsPointer);
        this.scopeOwner = new StoredMapU256(scopeOwnerPointer);
        this.scopeCreated = new StoredMapU256(scopeCreatedPointer);
        this.scopePendingOwner = new StoredMapU256(scopePendingOwnerPointer);
        this.scopePendingTimestamp = new StoredMapU256(scopePendingTimestampPointer);

        // Initialize package storage
        this.packageExists = new StoredMapU256(packageExistsPointer);
        this.packageOwner = new StoredMapU256(packageOwnerPointer);
        this.packageCreated = new StoredMapU256(packageCreatedPointer);
        this.packageVersionCount = new StoredMapU256(packageVersionCountPointer);
        this.pkgPendingOwner = new StoredMapU256(pkgPendingOwnerPointer);
        this.pkgPendingTimestamp = new StoredMapU256(pkgPendingTimestampPointer);

        // Initialize version storage
        this.versionExists = new StoredMapU256(versionExistsPointer);
        this.versionChecksum = new StoredMapU256(versionChecksumPointer);
        this.versionSigHash = new StoredMapU256(versionSigHashPointer);
        this.versionMldsaLevel = new StoredMapU256(versionMldsaLevelPointer);
        this.versionPluginType = new StoredMapU256(versionPluginTypePointer);
        this.versionPermHash = new StoredMapU256(versionPermHashPointer);
        this.versionDepsHash = new StoredMapU256(versionDepsHashPointer);
        this.versionPublisher = new StoredMapU256(versionPublisherPointer);
        this.versionTimestamp = new StoredMapU256(versionTimestampPointer);
        this.versionDeprecated = new StoredMapU256(versionDeprecatedPointer);
    }

    // -------------------------------------------------------------------------
    // Deployment Initialization
    // -------------------------------------------------------------------------
    public override onDeployment(calldata: Calldata): void {
        // Read optional treasury address from calldata, or use deployer's P2TR address
        const treasuryAddr = calldata.readStringWithLength();
        if (treasuryAddr.length > 0) {
            this.treasuryAddress.value = treasuryAddr;
        } else {
            this.treasuryAddress.value = Blockchain.tx.origin.p2tr();
        }

        // Set default prices
        this.scopePriceSats.set(u256.Zero, u256.fromU64(DEFAULT_SCOPE_PRICE_SATS));
        this.packagePriceSats.set(u256.Zero, u256.fromU64(DEFAULT_PACKAGE_PRICE_SATS));

        // Reserve @opnet scope for deployer
        const opnetScopeKey = this.getScopeKeyU256(RESERVED_SCOPE);
        const blockNumber = Blockchain.block.number;
        const deployer = Blockchain.tx.origin;

        this.scopeExists.set(opnetScopeKey, u256.One);
        this.scopeOwner.set(opnetScopeKey, this._addressToU256(deployer));
        this.scopeCreated.set(opnetScopeKey, u256.fromU64(blockNumber));

        this.emitEvent(new ScopeRegisteredEvent(opnetScopeKey, deployer, blockNumber));
    }

    // =========================================================================
    // ADMIN METHODS (Owner Only)
    // =========================================================================

    /**
     * Set the treasury address for receiving payments.
     * @param calldata Contains the new treasury address as a string.
     */
    @method({ name: 'treasuryAddress', type: ABIDataTypes.STRING })
    @emit('TreasuryAddressChanged')
    public setTreasuryAddress(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const newAddress = calldata.readStringWithLength();
        if (newAddress.length == 0) {
            throw new Revert('Invalid treasury address');
        }

        this.validateTreasuryAddress(newAddress);

        const oldAddressHash = this.stringToU256Hash(this.treasuryAddress.value);
        const newAddressHash = this.stringToU256Hash(newAddress);

        this.treasuryAddress.value = newAddress;

        this.emitEvent(
            new TreasuryAddressChangedEvent(
                oldAddressHash,
                newAddressHash,
                Blockchain.block.number,
            ),
        );

        return new BytesWriter(0);
    }

    /**
     * Set the price for registering a scope.
     * @param calldata Contains the new price in satoshis (u64).
     */
    @method({ name: 'priceSats', type: ABIDataTypes.UINT64 })
    @emit('ScopePriceChanged')
    public setScopePrice(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const newPrice = calldata.readU64();
        const oldPrice = this.scopePriceSats.get(u256.Zero).toU64();

        this.scopePriceSats.set(u256.Zero, u256.fromU64(newPrice));

        this.emitEvent(new ScopePriceChangedEvent(oldPrice, newPrice, Blockchain.block.number));

        return new BytesWriter(0);
    }

    /**
     * Set the price for registering an unscoped package.
     * @param calldata Contains the new price in satoshis (u64).
     */
    @method({ name: 'priceSats', type: ABIDataTypes.UINT64 })
    @emit('PackagePriceChanged')
    public setPackagePrice(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const newPrice = calldata.readU64();
        const oldPrice = this.packagePriceSats.get(u256.Zero).toU64();

        this.packagePriceSats.set(u256.Zero, u256.fromU64(newPrice));

        this.emitEvent(new PackagePriceChangedEvent(oldPrice, newPrice, Blockchain.block.number));

        return new BytesWriter(0);
    }

    // =========================================================================
    // SCOPE METHODS
    // =========================================================================

    /**
     * Register a new scope. Requires payment to treasury.
     * @param calldata Contains the scope name (without @).
     */
    @method({ name: 'scopeName', type: ABIDataTypes.STRING })
    @emit('ScopeRegistered')
    public registerScope(calldata: Calldata): BytesWriter {
        const scopeName = calldata.readStringWithLength();

        // Validate scope name
        this.validateScopeName(scopeName);

        // Check if reserved
        if (scopeName == RESERVED_SCOPE) {
            throw new Revert('Scope is reserved');
        }

        const scopeKey = this.getScopeKeyU256(scopeName);

        // Check if already exists
        if (!this.scopeExists.get(scopeKey).isZero()) {
            throw new Revert('Scope already exists');
        }

        // Verify payment
        this.verifyPayment(this.scopePriceSats.get(u256.Zero).toU64());

        // Register scope
        const blockNumber = Blockchain.block.number;
        const sender = Blockchain.tx.sender;

        this.scopeExists.set(scopeKey, u256.One);
        this.scopeOwner.set(scopeKey, this._addressToU256(sender));
        this.scopeCreated.set(scopeKey, u256.fromU64(blockNumber));

        this.emitEvent(new ScopeRegisteredEvent(scopeKey, sender, blockNumber));

        return new BytesWriter(0);
    }

    /**
     * Initiate transfer of scope ownership.
     * @param calldata Contains scope name and new owner address.
     */
    @method(
        { name: 'scopeName', type: ABIDataTypes.STRING },
        { name: 'newOwner', type: ABIDataTypes.ADDRESS },
    )
    @emit('ScopeTransferInitiated')
    public initiateScopeTransfer(calldata: Calldata): BytesWriter {
        const scopeName = calldata.readStringWithLength();
        const newOwner = calldata.readAddress();

        const scopeKey = this.getScopeKeyU256(scopeName);

        // Verify caller is owner
        this.requireScopeOwner(scopeKey);

        // Validate new owner
        if (newOwner.equals(Address.zero())) {
            throw new Revert('Invalid new owner');
        }

        // Set pending transfer
        const blockNumber = Blockchain.block.number;
        this.scopePendingOwner.set(scopeKey, this._addressToU256(newOwner));
        this.scopePendingTimestamp.set(scopeKey, u256.fromU64(blockNumber));

        this.emitEvent(
            new ScopeTransferInitiatedEvent(scopeKey, Blockchain.tx.sender, newOwner, blockNumber),
        );

        return new BytesWriter(0);
    }

    /**
     * Accept a pending scope transfer.
     * @param calldata Contains the scope name.
     */
    @method({ name: 'scopeName', type: ABIDataTypes.STRING })
    @emit('ScopeTransferCompleted')
    public acceptScopeTransfer(calldata: Calldata): BytesWriter {
        const scopeName = calldata.readStringWithLength();
        const scopeKey = this.getScopeKeyU256(scopeName);

        // Verify pending transfer exists
        const pendingOwner = this._u256ToAddress(this.scopePendingOwner.get(scopeKey));
        if (pendingOwner.equals(Address.zero())) {
            throw new Revert('No pending transfer');
        }

        // Verify caller is pending owner
        if (!Blockchain.tx.sender.equals(pendingOwner)) {
            throw new Revert('Not pending owner');
        }

        // Complete transfer
        const previousOwner = this._u256ToAddress(this.scopeOwner.get(scopeKey));
        const blockNumber = Blockchain.block.number;

        this.scopeOwner.set(scopeKey, this._addressToU256(pendingOwner));
        this.scopePendingOwner.set(scopeKey, u256.Zero);
        this.scopePendingTimestamp.set(scopeKey, u256.Zero);

        this.emitEvent(
            new ScopeTransferCompletedEvent(scopeKey, previousOwner, pendingOwner, blockNumber),
        );

        return new BytesWriter(0);
    }

    /**
     * Cancel a pending scope transfer.
     * @param calldata Contains the scope name.
     */
    @method({ name: 'scopeName', type: ABIDataTypes.STRING })
    @emit('ScopeTransferCancelled')
    public cancelScopeTransfer(calldata: Calldata): BytesWriter {
        const scopeName = calldata.readStringWithLength();
        const scopeKey = this.getScopeKeyU256(scopeName);

        // Verify caller is owner
        this.requireScopeOwner(scopeKey);

        // Verify there is a pending transfer to cancel
        if (this.scopePendingOwner.get(scopeKey).isZero()) {
            throw new Revert('No pending scope transfer');
        }

        // Clear pending transfer
        this.scopePendingOwner.set(scopeKey, u256.Zero);
        this.scopePendingTimestamp.set(scopeKey, u256.Zero);

        this.emitEvent(
            new ScopeTransferCancelledEvent(
                scopeKey,
                Blockchain.tx.sender,
                Blockchain.block.number,
            ),
        );

        return new BytesWriter(0);
    }

    // =========================================================================
    // PACKAGE METHODS
    // =========================================================================

    /**
     * Register a new package.
     * For scoped packages (@scope/name), caller must own the scope (free).
     * For unscoped packages, requires payment.
     * @param calldata Contains the full package name.
     */
    @method({ name: 'packageName', type: ABIDataTypes.STRING })
    @emit('PackageRegistered')
    public registerPackage(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();

        // Validate package name
        this.validatePackageName(packageName);

        const packageKey = this.getPackageKeyU256(packageName);

        // Check if already exists
        if (!this.packageExists.get(packageKey).isZero()) {
            throw new Revert('Package already exists');
        }

        const sender = Blockchain.tx.sender;
        const blockNumber = Blockchain.block.number;

        // Check if scoped package
        if (this.isScoped(packageName)) {
            const scopeName = this.extractScope(packageName);
            const scopeKey = this.getScopeKeyU256(scopeName);

            // Verify scope exists
            if (this.scopeExists.get(scopeKey).isZero()) {
                throw new Revert('Scope does not exist');
            }

            // Verify caller owns scope (scoped packages are free for scope owner)
            const scopeOwnerAddr = this._u256ToAddress(this.scopeOwner.get(scopeKey));
            if (!sender.equals(scopeOwnerAddr)) {
                throw new Revert('Not scope owner');
            }
        } else {
            // Unscoped package requires payment
            this.verifyPayment(this.packagePriceSats.get(u256.Zero).toU64());
        }

        // Register package
        this.packageExists.set(packageKey, u256.One);
        this.packageOwner.set(packageKey, this._addressToU256(sender));
        this.packageCreated.set(packageKey, u256.fromU64(blockNumber));
        this.packageVersionCount.set(packageKey, u256.Zero);

        this.emitEvent(new PackageRegisteredEvent(packageKey, sender, blockNumber));

        return new BytesWriter(0);
    }

    /**
     * Publish a new version of a package.
     * @param calldata Contains version metadata.
     */
    @method(
        { name: 'packageName', type: ABIDataTypes.STRING },
        { name: 'version', type: ABIDataTypes.STRING },
        { name: 'ipfsCid', type: ABIDataTypes.STRING },
        { name: 'checksum', type: ABIDataTypes.BYTES32 },
        { name: 'signature', type: ABIDataTypes.BYTES },
        { name: 'mldsaLevel', type: ABIDataTypes.UINT8 },
        { name: 'opnetVersionRange', type: ABIDataTypes.STRING },
        { name: 'pluginType', type: ABIDataTypes.UINT8 },
        { name: 'permissionsHash', type: ABIDataTypes.BYTES32 },
        { name: 'dependencies', type: ABIDataTypes.BYTES },
    )
    @emit('VersionPublished')
    public publishVersion(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const version = calldata.readStringWithLength();
        const ipfsCid = calldata.readStringWithLength();
        const checksum = calldata.readU256();
        const signature = calldata.readBytesWithLength();
        const mldsaLevel = calldata.readU8();
        const opnetVersionRange = calldata.readStringWithLength();
        const pluginType = calldata.readU8();
        const permissionsHash = calldata.readU256();
        const dependencies = calldata.readBytesWithLength();

        const packageKey = this.getPackageKeyU256(packageName);

        // Verify package exists
        if (this.packageExists.get(packageKey).isZero()) {
            throw new Revert('Package does not exist');
        }

        // Verify caller is owner
        this.requirePackageOwner(packageKey);

        // Validate inputs
        this.validateVersionString(version);
        this.validateIpfsCid(ipfsCid);
        this.validateChecksum(checksum);
        this.validateOpnetVersionRange(opnetVersionRange);

        if (mldsaLevel < 1 || mldsaLevel > 3) {
            throw new Revert('Invalid MLDSA level');
        }

        this.validateSignatureLength(signature, mldsaLevel);

        if (pluginType < 1 || pluginType > 2) {
            throw new Revert('Invalid plugin type');
        }

        // Create version key
        const versionKey = this.getVersionKeyU256(packageName, version);

        // Check version doesn't already exist
        if (!this.versionExists.get(versionKey).isZero()) {
            throw new Revert('Version already exists');
        }

        const sender = Blockchain.tx.sender;
        const blockNumber = Blockchain.block.number;

        // Store signature hash (signature too large for on-chain storage)
        const sigHash = u256.fromUint8ArrayBE(Blockchain.sha256(signature));

        // Store dependencies hash
        const depsHash = u256.fromUint8ArrayBE(Blockchain.sha256(dependencies));

        // Store version data
        this.versionExists.set(versionKey, u256.One);
        this.versionChecksum.set(versionKey, checksum);
        this.versionSigHash.set(versionKey, sigHash);
        this.versionMldsaLevel.set(versionKey, u256.fromU32(<u32>mldsaLevel));
        this.versionPluginType.set(versionKey, u256.fromU32(<u32>pluginType));
        this.versionPermHash.set(versionKey, permissionsHash);
        this.versionDepsHash.set(versionKey, depsHash);
        this.versionPublisher.set(versionKey, this._addressToU256(sender));
        this.versionTimestamp.set(versionKey, u256.fromU64(blockNumber));
        this.versionDeprecated.set(versionKey, u256.Zero);

        // Store variable-length strings using AdvancedStoredString
        const versionKeyBytes = this.getVersionKey(packageName, version);
        const cidStorage = new AdvancedStoredString(
            versionIpfsCidPointer,
            versionKeyBytes,
            MAX_CID_LENGTH,
        );
        cidStorage.value = ipfsCid;

        const rangeStorage = new AdvancedStoredString(
            versionOpnetRangePointer,
            versionKeyBytes,
            MAX_OPNET_RANGE_LENGTH,
        );
        rangeStorage.value = opnetVersionRange;

        // Store latest version for package
        const pkgKeyBytes = this.getPackageKey(packageName);
        const latestStorage = new AdvancedStoredString(
            packageLatestVersionPointer,
            pkgKeyBytes,
            MAX_VERSION_LENGTH,
        );
        latestStorage.value = version;

        // Increment version count
        const currentCount = this.packageVersionCount.get(packageKey);
        this.packageVersionCount.set(packageKey, SafeMath.add(currentCount, u256.One));

        this.emitEvent(
            new VersionPublishedEvent(
                packageKey,
                versionKey,
                sender,
                checksum,
                blockNumber,
                mldsaLevel,
                pluginType,
            ),
        );

        return new BytesWriter(0);
    }

    /**
     * Deprecate a version (within 72-hour window).
     * @param calldata Contains package name, version, and reason.
     */
    @method(
        { name: 'packageName', type: ABIDataTypes.STRING },
        { name: 'version', type: ABIDataTypes.STRING },
        { name: 'reason', type: ABIDataTypes.STRING },
    )
    @emit('VersionDeprecated')
    public deprecateVersion(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const version = calldata.readStringWithLength();
        const reason = calldata.readStringWithLength();

        const packageKey = this.getPackageKeyU256(packageName);
        const versionKey = this.getVersionKeyU256(packageName, version);

        // Verify package and version exist
        if (this.packageExists.get(packageKey).isZero()) {
            throw new Revert('Package does not exist');
        }

        if (this.versionExists.get(versionKey).isZero()) {
            throw new Revert('Version does not exist');
        }

        // Verify caller is owner
        this.requirePackageOwner(packageKey);

        // Check within mutability window
        const publishTime = this.versionTimestamp.get(versionKey).toU64();
        if (!this.isWithinMutabilityWindow(publishTime)) {
            throw new Revert('Version is immutable');
        }

        // Check not already deprecated
        if (!this.versionDeprecated.get(versionKey).isZero()) {
            throw new Revert('Already deprecated');
        }

        // Mark as deprecated
        this.versionDeprecated.set(versionKey, u256.One);

        // Store deprecation reason
        const versionKeyBytes = this.getVersionKey(packageName, version);
        const reasonStorage = new AdvancedStoredString(
            versionDepReasonPointer,
            versionKeyBytes,
            MAX_REASON_LENGTH,
        );
        reasonStorage.value = reason;

        this.emitEvent(new VersionDeprecatedEvent(packageKey, versionKey, Blockchain.block.number));

        return new BytesWriter(0);
    }

    /**
     * Undeprecate a version (within 72-hour window).
     * @param calldata Contains package name and version.
     */
    @method(
        { name: 'packageName', type: ABIDataTypes.STRING },
        { name: 'version', type: ABIDataTypes.STRING },
    )
    @emit('VersionUndeprecated')
    public undeprecateVersion(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const version = calldata.readStringWithLength();

        const packageKey = this.getPackageKeyU256(packageName);
        const versionKey = this.getVersionKeyU256(packageName, version);

        // Verify package and version exist
        if (this.packageExists.get(packageKey).isZero()) {
            throw new Revert('Package does not exist');
        }

        if (this.versionExists.get(versionKey).isZero()) {
            throw new Revert('Version does not exist');
        }

        // Verify caller is owner
        this.requirePackageOwner(packageKey);

        // Check within mutability window
        const publishTime = this.versionTimestamp.get(versionKey).toU64();
        if (!this.isWithinMutabilityWindow(publishTime)) {
            throw new Revert('Version is immutable');
        }

        // Check is deprecated
        if (this.versionDeprecated.get(versionKey).isZero()) {
            throw new Revert('Not deprecated');
        }

        // Mark as not deprecated
        this.versionDeprecated.set(versionKey, u256.Zero);

        // Clear deprecation reason
        const versionKeyBytes = this.getVersionKey(packageName, version);
        const reasonStorage = new AdvancedStoredString(
            versionDepReasonPointer,
            versionKeyBytes,
            MAX_REASON_LENGTH,
        );
        reasonStorage.value = '';

        this.emitEvent(
            new VersionUndeprecatedEvent(packageKey, versionKey, Blockchain.block.number),
        );

        return new BytesWriter(0);
    }

    /**
     * Initiate transfer of package ownership.
     * @param calldata Contains package name and new owner address.
     */
    @method(
        { name: 'packageName', type: ABIDataTypes.STRING },
        { name: 'newOwner', type: ABIDataTypes.ADDRESS },
    )
    @emit('PackageTransferInitiated')
    public initiateTransfer(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const newOwner = calldata.readAddress();

        const packageKey = this.getPackageKeyU256(packageName);

        // Verify caller is owner
        this.requirePackageOwner(packageKey);

        // Validate new owner
        if (newOwner.equals(Address.zero())) {
            throw new Revert('Invalid new owner');
        }

        // Set pending transfer
        const blockNumber = Blockchain.block.number;
        this.pkgPendingOwner.set(packageKey, this._addressToU256(newOwner));
        this.pkgPendingTimestamp.set(packageKey, u256.fromU64(blockNumber));

        this.emitEvent(
            new PackageTransferInitiatedEvent(
                packageKey,
                Blockchain.tx.sender,
                newOwner,
                blockNumber,
            ),
        );

        return new BytesWriter(0);
    }

    /**
     * Accept a pending package transfer.
     * @param calldata Contains the package name.
     */
    @method({ name: 'packageName', type: ABIDataTypes.STRING })
    @emit('PackageTransferCompleted')
    public acceptTransfer(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const packageKey = this.getPackageKeyU256(packageName);

        // Verify pending transfer exists
        const pendingOwner = this._u256ToAddress(this.pkgPendingOwner.get(packageKey));
        if (pendingOwner.equals(Address.zero())) {
            throw new Revert('No pending transfer');
        }

        // Verify caller is pending owner
        if (!Blockchain.tx.sender.equals(pendingOwner)) {
            throw new Revert('Not pending owner');
        }

        // Complete transfer
        const previousOwner = this._u256ToAddress(this.packageOwner.get(packageKey));
        const blockNumber = Blockchain.block.number;

        this.packageOwner.set(packageKey, this._addressToU256(pendingOwner));
        this.pkgPendingOwner.set(packageKey, u256.Zero);
        this.pkgPendingTimestamp.set(packageKey, u256.Zero);

        this.emitEvent(
            new PackageTransferCompletedEvent(packageKey, previousOwner, pendingOwner, blockNumber),
        );

        return new BytesWriter(0);
    }

    /**
     * Cancel a pending package transfer.
     * @param calldata Contains the package name.
     */
    @method({ name: 'packageName', type: ABIDataTypes.STRING })
    @emit('PackageTransferCancelled')
    public cancelTransfer(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const packageKey = this.getPackageKeyU256(packageName);

        // Verify caller is owner
        this.requirePackageOwner(packageKey);

        // Verify there is a pending transfer to cancel
        if (this.pkgPendingOwner.get(packageKey).isZero()) {
            throw new Revert('No pending transfer');
        }

        // Clear pending transfer
        this.pkgPendingOwner.set(packageKey, u256.Zero);
        this.pkgPendingTimestamp.set(packageKey, u256.Zero);

        this.emitEvent(
            new PackageTransferCancelledEvent(
                packageKey,
                Blockchain.tx.sender,
                Blockchain.block.number,
            ),
        );

        return new BytesWriter(0);
    }

    // =========================================================================
    // VIEW METHODS
    // =========================================================================

    /**
     * Get scope information.
     * @returns exists, owner, createdAt
     */
    @method({ name: 'scopeName', type: ABIDataTypes.STRING })
    @returns(
        { name: 'exists', type: ABIDataTypes.BOOL },
        { name: 'owner', type: ABIDataTypes.ADDRESS },
        { name: 'createdAt', type: ABIDataTypes.UINT64 },
    )
    public getScope(calldata: Calldata): BytesWriter {
        const scopeName = calldata.readStringWithLength();
        const scopeKey = this.getScopeKeyU256(scopeName);

        const exists = !this.scopeExists.get(scopeKey).isZero();
        const owner = exists ? this._u256ToAddress(this.scopeOwner.get(scopeKey)) : Address.zero();
        const createdAt = exists ? this.scopeCreated.get(scopeKey).toU64() : <u64>0;

        const response = new BytesWriter(1 + 32 + 8);
        response.writeBoolean(exists);
        response.writeAddress(owner);
        response.writeU64(createdAt);

        return response;
    }

    /**
     * Get scope owner address.
     * @returns owner address
     */
    @method({ name: 'scopeName', type: ABIDataTypes.STRING })
    @returns({ name: 'owner', type: ABIDataTypes.ADDRESS })
    public getScopeOwner(calldata: Calldata): BytesWriter {
        const scopeName = calldata.readStringWithLength();
        const scopeKey = this.getScopeKeyU256(scopeName);

        const owner = this._u256ToAddress(this.scopeOwner.get(scopeKey));

        const response = new BytesWriter(32);
        response.writeAddress(owner);

        return response;
    }

    /**
     * Get package information.
     * @returns exists, owner, createdAt, versionCount, latestVersion
     */
    @method({ name: 'packageName', type: ABIDataTypes.STRING })
    @returns(
        { name: 'exists', type: ABIDataTypes.BOOL },
        { name: 'owner', type: ABIDataTypes.ADDRESS },
        { name: 'createdAt', type: ABIDataTypes.UINT64 },
        { name: 'versionCount', type: ABIDataTypes.UINT256 },
        { name: 'latestVersion', type: ABIDataTypes.STRING },
    )
    public getPackage(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const packageKey = this.getPackageKeyU256(packageName);
        const pkgKeyBytes = this.getPackageKey(packageName);

        const exists = !this.packageExists.get(packageKey).isZero();
        const owner = exists
            ? this._u256ToAddress(this.packageOwner.get(packageKey))
            : Address.zero();
        const createdAt = exists ? this.packageCreated.get(packageKey).toU64() : <u64>0;
        const versionCount = exists ? this.packageVersionCount.get(packageKey) : u256.Zero;

        let latestVersion = '';
        if (exists) {
            const latestStorage = new AdvancedStoredString(
                packageLatestVersionPointer,
                pkgKeyBytes,
                32,
            );
            latestVersion = latestStorage.value;
        }

        // Calculate response size
        const latestBytes = Uint8Array.wrap(String.UTF8.encode(latestVersion));
        const response = new BytesWriter(1 + 32 + 8 + 32 + 4 + latestBytes.length);
        response.writeBoolean(exists);
        response.writeAddress(owner);
        response.writeU64(createdAt);
        response.writeU256(versionCount);
        response.writeStringWithLength(latestVersion);

        return response;
    }

    /**
     * Get package owner address.
     * @returns owner address
     */
    @method({ name: 'packageName', type: ABIDataTypes.STRING })
    @returns({ name: 'owner', type: ABIDataTypes.ADDRESS })
    public getOwner(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const packageKey = this.getPackageKeyU256(packageName);

        const owner = this._u256ToAddress(this.packageOwner.get(packageKey));

        const response = new BytesWriter(32);
        response.writeAddress(owner);

        return response;
    }

    /**
     * Get version information.
     * @returns Full version metadata
     */
    @method(
        { name: 'packageName', type: ABIDataTypes.STRING },
        { name: 'version', type: ABIDataTypes.STRING },
    )
    @returns(
        { name: 'exists', type: ABIDataTypes.BOOL },
        { name: 'ipfsCid', type: ABIDataTypes.STRING },
        { name: 'checksum', type: ABIDataTypes.BYTES32 },
        { name: 'sigHash', type: ABIDataTypes.BYTES32 },
        { name: 'mldsaLevel', type: ABIDataTypes.UINT8 },
        { name: 'opnetVersionRange', type: ABIDataTypes.STRING },
        { name: 'pluginType', type: ABIDataTypes.UINT8 },
        { name: 'permissionsHash', type: ABIDataTypes.BYTES32 },
        { name: 'depsHash', type: ABIDataTypes.BYTES32 },
        { name: 'publisher', type: ABIDataTypes.ADDRESS },
        { name: 'publishedAt', type: ABIDataTypes.UINT64 },
        { name: 'deprecated', type: ABIDataTypes.BOOL },
    )
    public getVersion(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const version = calldata.readStringWithLength();

        const versionKey = this.getVersionKeyU256(packageName, version);
        const versionKeyBytes = this.getVersionKey(packageName, version);

        const exists = !this.versionExists.get(versionKey).isZero();

        if (!exists) {
            const response = new BytesWriter(1);
            response.writeBoolean(false);
            return response;
        }

        const checksum = this.versionChecksum.get(versionKey);
        const sigHash = this.versionSigHash.get(versionKey);
        const mldsaLevel = <u8>this.versionMldsaLevel.get(versionKey).toU32();
        const pluginType = <u8>this.versionPluginType.get(versionKey).toU32();
        const permissionsHash = this.versionPermHash.get(versionKey);
        const depsHash = this.versionDepsHash.get(versionKey);
        const publisher = this._u256ToAddress(this.versionPublisher.get(versionKey));
        const publishedAt = this.versionTimestamp.get(versionKey).toU64();
        const deprecated = !this.versionDeprecated.get(versionKey).isZero();

        const cidStorage = new AdvancedStoredString(
            versionIpfsCidPointer,
            versionKeyBytes,
            MAX_CID_LENGTH,
        );
        const ipfsCid = cidStorage.value;

        const rangeStorage = new AdvancedStoredString(
            versionOpnetRangePointer,
            versionKeyBytes,
            MAX_OPNET_RANGE_LENGTH,
        );
        const opnetVersionRange = rangeStorage.value;

        // Calculate response size
        const cidBytes = Uint8Array.wrap(String.UTF8.encode(ipfsCid));
        const rangeBytes = Uint8Array.wrap(String.UTF8.encode(opnetVersionRange));

        const response = new BytesWriter(
            1 + // exists
                4 +
                cidBytes.length + // ipfsCid
                32 + // checksum
                32 + // sigHash
                1 + // mldsaLevel
                4 +
                rangeBytes.length + // opnetVersionRange
                1 + // pluginType
                32 + // permissionsHash
                32 + // depsHash
                32 + // publisher
                8 + // publishedAt
                1, // deprecated
        );

        response.writeBoolean(exists);
        response.writeStringWithLength(ipfsCid);
        response.writeU256(checksum);
        response.writeU256(sigHash);
        response.writeU8(mldsaLevel);
        response.writeStringWithLength(opnetVersionRange);
        response.writeU8(pluginType);
        response.writeU256(permissionsHash);
        response.writeU256(depsHash);
        response.writeAddress(publisher);
        response.writeU64(publishedAt);
        response.writeBoolean(deprecated);

        return response;
    }

    /**
     * Check if a version is deprecated.
     * @returns boolean
     */
    @method(
        { name: 'packageName', type: ABIDataTypes.STRING },
        { name: 'version', type: ABIDataTypes.STRING },
    )
    @returns({ name: 'deprecated', type: ABIDataTypes.BOOL })
    public isDeprecated(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const version = calldata.readStringWithLength();

        const versionKey = this.getVersionKeyU256(packageName, version);

        const deprecated = !this.versionDeprecated.get(versionKey).isZero();

        const response = new BytesWriter(1);
        response.writeBoolean(deprecated);

        return response;
    }

    /**
     * Check if a version is immutable (past 72-hour window).
     * @returns boolean
     */
    @method(
        { name: 'packageName', type: ABIDataTypes.STRING },
        { name: 'version', type: ABIDataTypes.STRING },
    )
    @returns({ name: 'immutable', type: ABIDataTypes.BOOL })
    public isImmutable(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const version = calldata.readStringWithLength();

        const versionKey = this.getVersionKeyU256(packageName, version);

        if (this.versionExists.get(versionKey).isZero()) {
            const response = new BytesWriter(1);
            response.writeBoolean(false);
            return response;
        }

        const publishTime = this.versionTimestamp.get(versionKey).toU64();
        const immutable = !this.isWithinMutabilityWindow(publishTime);

        const response = new BytesWriter(1);
        response.writeBoolean(immutable);

        return response;
    }

    /**
     * Get pending transfer info for a package.
     * @returns pendingOwner, initiatedAt
     */
    @method({ name: 'packageName', type: ABIDataTypes.STRING })
    @returns(
        { name: 'pendingOwner', type: ABIDataTypes.ADDRESS },
        { name: 'initiatedAt', type: ABIDataTypes.UINT64 },
    )
    public getPendingTransfer(calldata: Calldata): BytesWriter {
        const packageName = calldata.readStringWithLength();
        const packageKey = this.getPackageKeyU256(packageName);

        const pendingOwner = this._u256ToAddress(this.pkgPendingOwner.get(packageKey));
        const initiatedAt = this.pkgPendingTimestamp.get(packageKey).toU64();

        const response = new BytesWriter(32 + 8);
        response.writeAddress(pendingOwner);
        response.writeU64(initiatedAt);

        return response;
    }

    /**
     * Get pending transfer info for a scope.
     * @returns pendingOwner, initiatedAt
     */
    @method({ name: 'scopeName', type: ABIDataTypes.STRING })
    @returns(
        { name: 'pendingOwner', type: ABIDataTypes.ADDRESS },
        { name: 'initiatedAt', type: ABIDataTypes.UINT64 },
    )
    public getPendingScopeTransfer(calldata: Calldata): BytesWriter {
        const scopeName = calldata.readStringWithLength();
        const scopeKey = this.getScopeKeyU256(scopeName);

        const pendingOwner = this._u256ToAddress(this.scopePendingOwner.get(scopeKey));
        const initiatedAt = this.scopePendingTimestamp.get(scopeKey).toU64();

        const response = new BytesWriter(32 + 8);
        response.writeAddress(pendingOwner);
        response.writeU64(initiatedAt);

        return response;
    }

    /**
     * Get current treasury address.
     * @returns treasury address string
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
     * Get current scope price.
     * @returns price in satoshis
     */
    @method()
    @returns({ name: 'priceSats', type: ABIDataTypes.UINT64 })
    public getScopePrice(_: Calldata): BytesWriter {
        const response = new BytesWriter(8);
        response.writeU64(this.scopePriceSats.get(u256.Zero).toU64());

        return response;
    }

    /**
     * Get current package price.
     * @returns price in satoshis
     */
    @method()
    @returns({ name: 'priceSats', type: ABIDataTypes.UINT64 })
    public getPackagePrice(_: Calldata): BytesWriter {
        const response = new BytesWriter(8);
        response.writeU64(this.packagePriceSats.get(u256.Zero).toU64());

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

    private getScopeKeyU256(scopeName: string): u256 {
        const bytes = Uint8Array.wrap(String.UTF8.encode(scopeName));
        return u256.fromUint8ArrayBE(Blockchain.sha256(bytes));
    }

    /**
     * Generate a storage key for a package name.
     */
    private getPackageKey(packageName: string): Uint8Array {
        const bytes = Uint8Array.wrap(String.UTF8.encode(packageName));
        const hash = Blockchain.sha256(bytes);
        return hash.slice(0, 30);
    }

    private getPackageKeyU256(packageName: string): u256 {
        const bytes = Uint8Array.wrap(String.UTF8.encode(packageName));
        return u256.fromUint8ArrayBE(Blockchain.sha256(bytes));
    }

    /**
     * Generate a storage key for a version.
     */
    private getVersionKey(packageName: string, version: string): Uint8Array {
        const combined = packageName + ':' + version;
        const bytes = Uint8Array.wrap(String.UTF8.encode(combined));
        const hash = Blockchain.sha256(bytes);
        return hash.slice(0, 30);
    }

    private getVersionKeyU256(packageName: string, version: string): u256 {
        const combined = packageName + ':' + version;
        const bytes = Uint8Array.wrap(String.UTF8.encode(combined));
        return u256.fromUint8ArrayBE(Blockchain.sha256(bytes));
    }

    /**
     * Convert a string to a u256 hash.
     */
    private stringToU256Hash(str: string): u256 {
        const bytes = Uint8Array.wrap(String.UTF8.encode(str));
        return u256.fromUint8ArrayBE(Blockchain.sha256(bytes));
    }

    /**
     * Check if a package name is scoped.
     */
    private isScoped(packageName: string): boolean {
        return packageName.length > 0 && packageName.charCodeAt(0) == 64; // '@' = 64
    }

    /**
     * Extract scope name from a scoped package.
     */
    private extractScope(packageName: string): string {
        const slashIdx = packageName.indexOf('/');
        // slashIdx must be >= 2 (at least 1 char for scope after @)
        // and not at the end (must have package name after /)
        if (slashIdx < 2 || slashIdx >= packageName.length - 1) {
            throw new Revert('Invalid scoped package format');
        }
        return packageName.substring(1, slashIdx);
    }

    /**
     * Validate scope name format.
     */
    private validateScopeName(scope: string): void {
        const len = scope.length;
        if (len < 1 || len > <i32>MAX_SCOPE_LENGTH) {
            throw new Revert('Scope must be 1-32 characters');
        }

        const first = scope.charCodeAt(0);
        if (first < 97 || first > 122) {
            throw new Revert('Scope must start with lowercase letter');
        }

        for (let i = 1; i < len; i++) {
            const c = scope.charCodeAt(i);
            const isLower = c >= 97 && c <= 122;
            const isDigit = c >= 48 && c <= 57;
            const isHyphen = c == 45;

            if (!isLower && !isDigit && !isHyphen) {
                throw new Revert('Invalid character in scope');
            }
        }
    }

    /**
     * Validate package name format (scoped or unscoped).
     */
    private validatePackageName(name: string): void {
        if (this.isScoped(name)) {
            const slashIdx = name.indexOf('/');
            if (slashIdx < 2) {
                throw new Revert('Invalid scoped package format');
            }
            const scope = name.substring(1, slashIdx);
            const pkgName = name.substring(slashIdx + 1);
            this.validateScopeName(scope);
            this.validateUnscopedName(pkgName);
        } else {
            this.validateUnscopedName(name);
        }
    }

    /**
     * Validate unscoped package name format.
     */
    private validateUnscopedName(name: string): void {
        const len = name.length;
        if (len < 1 || len > <i32>MAX_NAME_LENGTH) {
            throw new Revert('Name must be 1-64 characters');
        }

        const first = name.charCodeAt(0);
        if (first < 97 || first > 122) {
            throw new Revert('Name must start with lowercase letter');
        }

        for (let i = 1; i < len; i++) {
            const c = name.charCodeAt(i);
            const isLower = c >= 97 && c <= 122;
            const isDigit = c >= 48 && c <= 57;
            const isHyphen = c == 45;

            if (!isLower && !isDigit && !isHyphen) {
                throw new Revert('Invalid character in name');
            }
        }
    }

    /**
     * Validate IPFS CID format.
     */
    private validateIpfsCid(cid: string): void {
        const len = cid.length;
        if (len < 46 || len > <i32>MAX_CID_LENGTH) {
            throw new Revert('CID must be 46-128 characters');
        }

        // CIDv0: starts with "Qm" (base58btc, 46 chars)
        const isV0 = cid.charCodeAt(0) == 81 && cid.charCodeAt(1) == 109; // "Qm"

        // CIDv1: starts with "baf" (base32, covers bafy, bafk, bafz, etc.)
        const isV1 = cid.charCodeAt(0) == 98 && cid.charCodeAt(1) == 97 && cid.charCodeAt(2) == 102; // "baf"

        if (!isV0 && !isV1) {
            throw new Revert('CID must start with Qm or baf');
        }
    }

    /**
     * Validate version string format (basic semver: major.minor.patch).
     * Allows optional pre-release suffix (e.g., 1.0.0-alpha.1).
     */
    private validateVersionString(version: string): void {
        const len = version.length;
        if (len < 5 || len > <i32>MAX_VERSION_LENGTH) {
            throw new Revert('Version must be 5-32 characters');
        }

        // Must start with a digit (major version)
        const first = version.charCodeAt(0);
        if (first < 48 || first > 57) {
            throw new Revert('Version must start with digit');
        }

        // Count dots - must have at least 2 for x.y.z
        let dotCount: i32 = 0;
        let lastWasDot = false;

        for (let i: i32 = 0; i < len; i++) {
            const c = version.charCodeAt(i);
            const isDot = c == 46; // '.'
            const isDigit = c >= 48 && c <= 57;
            const isHyphen = c == 45; // '-' for pre-release

            // After hyphen, we're in pre-release - allow alphanumeric and dots
            if (isHyphen) {
                if (dotCount < 2) {
                    throw new Revert('Invalid version format');
                }
                // Rest can be alphanumeric with dots
                break;
            }

            if (isDot) {
                if (lastWasDot) {
                    throw new Revert('Invalid version: consecutive dots');
                }
                dotCount++;
                lastWasDot = true;
            } else if (isDigit) {
                lastWasDot = false;
            } else {
                throw new Revert('Invalid character in version');
            }
        }

        if (dotCount < 2) {
            throw new Revert('Version must be semver (x.y.z)');
        }
    }

    /**
     * Validate OPNet version range string format.
     * Basic validation: must not be empty, must contain valid range characters.
     */
    private validateOpnetVersionRange(range: string): void {
        const len = range.length;
        if (len == 0 || len > <i32>MAX_OPNET_RANGE_LENGTH) {
            throw new Revert('OPNet range must be 1-64 characters');
        }

        // Must contain at least one digit (a version number)
        let hasDigit = false;
        for (let i: i32 = 0; i < len; i++) {
            const c = range.charCodeAt(i);
            if (c >= 48 && c <= 57) {
                hasDigit = true;
                break;
            }
        }

        if (!hasDigit) {
            throw new Revert('OPNet range must contain version number');
        }

        // Allow: digits, dots, spaces, comparison operators (<>=^~), logical (|&), x/*
        for (let i: i32 = 0; i < len; i++) {
            const c = range.charCodeAt(i);
            const isDigit = c >= 48 && c <= 57;
            const isDot = c == 46;
            const isSpace = c == 32;
            const isCompare = c == 60 || c == 62 || c == 61 || c == 94 || c == 126; // < > = ^ ~
            const isLogical = c == 124 || c == 38; // | &
            const isWildcard = c == 120 || c == 42; // x *
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
                throw new Revert('Invalid character in OPNet range');
            }
        }
    }

    /**
     * Validate treasury address format.
     * Accepts bc1p (taproot) or bc1q (segwit) addresses for mainnet.
     */
    private validateTreasuryAddress(address: string): void {
        const len = address.length;

        // Basic length check: bc1 addresses are 42-62 chars for segwit, 62 for taproot
        if (len < 42 || len > 62) {
            throw new Revert('Invalid treasury address length');
        }

        // Must start with bc1p (taproot) or bc1q (segwit)
        if (
            address.charCodeAt(0) != 98 || // 'b'
            address.charCodeAt(1) != 99 || // 'c'
            address.charCodeAt(2) != 49
        ) {
            // '1'
            throw new Revert('Treasury address must start with bc1');
        }

        const fourth = address.charCodeAt(3);
        if (fourth != 112 && fourth != 113) {
            // 'p' or 'q'
            throw new Revert('Treasury address must be bc1p or bc1q');
        }

        // Validate bech32 character set (lowercase alphanumeric except 1, b, i, o)
        for (let i: i32 = 4; i < len; i++) {
            const c = address.charCodeAt(i);
            // Valid bech32 chars: 023456789acdefghjklmnpqrstuvwxyz
            const isDigit = c >= 48 && c <= 57 && c != 49; // 0-9 except 1
            const isLower = c >= 97 && c <= 122 && c != 98 && c != 105 && c != 111; // a-z except b, i, o

            if (!isDigit && !isLower) {
                throw new Revert('Invalid character in treasury address');
            }
        }
    }

    /**
     * Validate checksum is non-zero (all-zero would indicate missing/invalid data).
     */
    private validateChecksum(checksum: u256): void {
        if (checksum.isZero()) {
            throw new Revert('Checksum cannot be zero');
        }
    }

    /**
     * Validate signature length matches expected size for MLDSA level.
     */
    private validateSignatureLength(signature: Uint8Array, mldsaLevel: u8): void {
        const sigLen = <u32>signature.length;
        let expectedLen: u32;

        if (mldsaLevel == 1) {
            expectedLen = MLDSA44_SIGNATURE_LEN;
        } else if (mldsaLevel == 2) {
            expectedLen = MLDSA65_SIGNATURE_LEN;
        } else if (mldsaLevel == 3) {
            expectedLen = MLDSA87_SIGNATURE_LEN;
        } else {
            throw new Revert('Invalid MLDSA level');
        }

        if (sigLen != expectedLen) {
            throw new Revert('Signature length mismatch for MLDSA level');
        }
    }

    /**
     * Check if block number is within 72-hour mutability window (~432 blocks).
     */
    private isWithinMutabilityWindow(publishBlock: u64): boolean {
        const currentBlock = Blockchain.block.number;
        return currentBlock <= publishBlock + MUTABILITY_WINDOW_BLOCKS;
    }

    /**
     * Verify payment to treasury address.
     */
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

    /**
     * Require caller to be the scope owner.
     */
    private requireScopeOwner(scopeKey: u256): void {
        if (this.scopeExists.get(scopeKey).isZero()) {
            throw new Revert('Scope does not exist');
        }

        const owner = this._u256ToAddress(this.scopeOwner.get(scopeKey));
        if (!Blockchain.tx.sender.equals(owner)) {
            throw new Revert('Not scope owner');
        }
    }

    /**
     * Require caller to be the package owner.
     */
    private requirePackageOwner(packageKey: u256): void {
        if (this.packageExists.get(packageKey).isZero()) {
            throw new Revert('Package does not exist');
        }

        const owner = this._u256ToAddress(this.packageOwner.get(packageKey));
        if (!Blockchain.tx.sender.equals(owner)) {
            throw new Revert('Not package owner');
        }
    }
}
