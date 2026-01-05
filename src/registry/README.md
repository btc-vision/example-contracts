# OPNet Package Registry Smart Contract

A decentralized package registry for OPNet plugins. Manages package ownership, version metadata, and deprecation status
entirely on-chain with IPFS for binary storage.

## Overview

The Package Registry serves as the canonical source of truth for:

- **Package ownership** - Tied to MLDSA public key hash
- **Version metadata** - IPFS CIDs, checksums, signatures, dependencies
- **Deprecation status** - With 72-hour mutability window
- **Scoped packages** - Like npm's `@org/package` format

## Pricing Model

### Scopes (`@scope`)

- Cost: ~$50 in BTC (adjustable by owner)
- Once owned, all sub-packages are **FREE**
- `@opnet` is reserved for the contract deployer

### Unscoped Packages

- Cost: 10,000 sats (adjustable by owner)
- First-come-first-served

## Building

```bash
npm install
npm run build:registry
```

The compiled WASM will be at `build/PackageRegistry.wasm`.

## Deployment

Deploy using the OP_WALLET browser extension or OPNet CLI.

### Deployment Calldata

The `onDeployment` method accepts an optional treasury address:

```typescript
// With custom treasury
calldata.writeStringWithLength('bc1p...your-treasury-address');

// Or empty string to use deployer's P2TR address
calldata.writeStringWithLength('');
```

## Contract Methods

### Admin Methods (Deployer Only)

| Method               | Parameters        | Description                    |
|----------------------|-------------------|--------------------------------|
| `setTreasuryAddress` | `address: string` | Set BTC address for payments   |
| `setScopePrice`      | `priceSats: u64`  | Set scope registration price   |
| `setPackagePrice`    | `priceSats: u64`  | Set package registration price |

### Scope Methods

| Method                  | Parameters                             | Description                             |
|-------------------------|----------------------------------------|-----------------------------------------|
| `registerScope`         | `scopeName: string`                    | Register a new scope (requires payment) |
| `initiateScopeTransfer` | `scopeName: string, newOwner: Address` | Start ownership transfer                |
| `acceptScopeTransfer`   | `scopeName: string`                    | Accept pending transfer                 |
| `cancelScopeTransfer`   | `scopeName: string`                    | Cancel pending transfer                 |

### Package Methods

| Method               | Parameters                     | Description                               |
|----------------------|--------------------------------|-------------------------------------------|
| `registerPackage`    | `packageName: string`          | Register a package (free for scope owner) |
| `publishVersion`     | See below                      | Publish a new version                     |
| `deprecateVersion`   | `packageName, version, reason` | Mark version deprecated (72h window)      |
| `undeprecateVersion` | `packageName, version`         | Remove deprecation (72h window)           |
| `initiateTransfer`   | `packageName, newOwner`        | Start ownership transfer                  |
| `acceptTransfer`     | `packageName`                  | Accept pending transfer                   |
| `cancelTransfer`     | `packageName`                  | Cancel pending transfer                   |

### publishVersion Parameters

```typescript
packageName: string; // Full package name (e.g., "@opnet/cli" or "my-plugin")
version: string; // Semver version (e.g., "1.0.0")
ipfsCid: string; // IPFS CID of the .opnet binary
checksum: Uint8Array; // SHA256 checksum of the binary (32 bytes)
signature: Uint8Array; // MLDSA signature bytes
mldsaLevel: u8; // 1=MLDSA44, 2=MLDSA65, 3=MLDSA87
opnetVersionRange: string; // Compatible OPNet versions (e.g., ">=1.0.0 <2.0.0")
pluginType: u8; // 1=standalone, 2=library
permissionsHash: Uint8Array; // SHA256 of permissions JSON (32 bytes)
dependencies: Uint8Array; // Encoded dependency array
```

### View Methods

| Method               | Parameters             | Returns                                                 |
|----------------------|------------------------|---------------------------------------------------------|
| `getScope`           | `scopeName`            | `exists, owner, createdAt`                              |
| `getScopeOwner`      | `scopeName`            | `owner`                                                 |
| `getPackage`         | `packageName`          | `exists, owner, createdAt, versionCount, latestVersion` |
| `getOwner`           | `packageName`          | `owner`                                                 |
| `getVersion`         | `packageName, version` | Full version metadata                                   |
| `isDeprecated`       | `packageName, version` | `deprecated: bool`                                      |
| `isImmutable`        | `packageName, version` | `immutable: bool`                                       |
| `getPendingTransfer` | `packageName`          | `pendingOwner, initiatedAt`                             |
| `getTreasuryAddress` | -                      | `treasuryAddress`                                       |
| `getScopePrice`      | -                      | `priceSats`                                             |
| `getPackagePrice`    | -                      | `priceSats`                                             |

## Events

### Scope Events

- `ScopeRegistered(scopeHash, owner, timestamp)`
- `ScopeTransferInitiated(scopeHash, currentOwner, newOwner, timestamp)`
- `ScopeTransferCompleted(scopeHash, previousOwner, newOwner, timestamp)`
- `ScopeTransferCancelled(scopeHash, owner, timestamp)`

### Package Events

- `PackageRegistered(packageHash, owner, timestamp)`
- `PackageTransferInitiated(packageHash, currentOwner, newOwner, timestamp)`
- `PackageTransferCompleted(packageHash, previousOwner, newOwner, timestamp)`
- `PackageTransferCancelled(packageHash, owner, timestamp)`

### Version Events

- `VersionPublished(packageHash, versionHash, publisher, checksum, timestamp, mldsaLevel, pluginType)`
- `VersionDeprecated(packageHash, versionHash, timestamp)`
- `VersionUndeprecated(packageHash, versionHash, timestamp)`

### Admin Events

- `TreasuryAddressChanged(previousAddressHash, newAddressHash, timestamp)`
- `ScopePriceChanged(oldPrice, newPrice, timestamp)`
- `PackagePriceChanged(oldPrice, newPrice, timestamp)`

## Validation Rules

### Package Names

- **Scoped**: `@scope/package-name`
    - Scope: `[a-z][a-z0-9-]*`, max 32 characters
    - Package: `[a-z][a-z0-9-]*`, max 64 characters
- **Unscoped**: `package-name`
    - Pattern: `[a-z][a-z0-9-]*`, max 64 characters

### IPFS CIDs

- Must start with `Qm` (CIDv0) or `baf` (CIDv1 - covers bafy, bafk, bafz, etc.)
- Length: 46-128 characters

### MLDSA Levels

- `1` = MLDSA-44 (~128-bit security)
- `2` = MLDSA-65 (~192-bit security)
- `3` = MLDSA-87 (~256-bit security)

### Plugin Types

- `1` = Standalone
- `2` = Library

## 72-Hour Mutability Window

Versions have a 72-hour grace period after publishing. During this window:

- Owner can deprecate or undeprecate the version
- Owner can update the deprecation reason

After 72 hours, the version becomes **fully immutable**. This protects downstream consumers while giving publishers time
to catch mistakes.

## Example Usage

### Register a Scope

```typescript
// Register @myorg scope
calldata.writeStringWithLength('myorg');
// Include payment of `getScopePrice()` sats to treasury address
```

### Register a Scoped Package

```typescript
// Register @myorg/my-plugin (free if you own @myorg)
calldata.writeStringWithLength('@myorg/my-plugin');
```

### Publish a Version

```typescript
calldata.writeStringWithLength('@myorg/my-plugin');
calldata.writeStringWithLength('1.0.0');
calldata.writeStringWithLength('QmYourIPFSCidHere...');
calldata.writeU256(checksumU256);
calldata.writeBytesWithLength(mldsaSignature);
calldata.writeU8(2); // MLDSA-65
calldata.writeStringWithLength('>=1.0.0 <2.0.0');
calldata.writeU8(1); // standalone
calldata.writeU256(permissionsHashU256);
calldata.writeBytesWithLength(encodedDependencies);
```

## Storage Architecture

The contract uses pointer-based storage with SHA256 hashes as composite keys:

- **Scope Key**: `SHA256(scopeName)`
- **Package Key**: `SHA256(packageName)`
- **Version Key**: `SHA256(packageName + ":" + version)`

Variable-length strings (IPFS CIDs, version ranges, deprecation reasons) use `AdvancedStoredString` which spans multiple
32-byte storage slots.

## Security Considerations

1. **Ownership**: Authority comes from transaction signature, which OPNet validates
2. **MLDSA Signatures**: Stored as SHA256 hash on-chain, full signature in events for client verification
3. **Payment Verification**: Verifies BTC outputs to treasury address
4. **Immutability**: 72-hour window prevents permanent mistakes while protecting consumers

## License

Apache-2.0
