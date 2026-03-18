import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    AddressMemoryMap,
    Blockchain,
    BytesWriter,
    Calldata,
    EMPTY_POINTER,
    OP_NET,
    Revert,
    SafeMath,
    StoredAddressArray,
    StoredString,
    StoredU256,
    StoredU256Array,
} from '@btc-vision/btc-runtime/runtime';
import { MintCounterEvent } from './events/MintCounterEvent';

/**
 * MintCounter
 *
 * Tracks global and per-user mint counts for the free-mint event.
 * Each call to mint() must include a >= 1,420 sat output to the treasury address.
 * No per-address cap. Minting closes when currentBlock >= endBlock.
 *
 * Leaderboard design:
 *   A sorted top-50 leaderboard is maintained at write time. Two parallel arrays
 *   (StoredAddressArray for addresses, StoredU256Array for counts) are kept in
 *   descending order by mint count. On every mint, the caller's new count is
 *   compared against the 50th entry; if it qualifies, it is inserted at the
 *   correct sorted position (or moved up if already present). This bounds the
 *   worst-case write overhead to ~50 storage operations per mint and makes
 *   leaderboard reads a trivial sequential fetch with zero sorting.
 *
 *   A separate append-only StoredAddressArray tracks all unique minters for
 *   full enumeration via paginated RPC calls.
 *
 *  Deployment calldata:
 *    treasury  string  — Bitcoin P2TR address receiving 1,420 sats per mint
 *    endBlock  u256    — block height at which minting closes (exclusive)
 */
@final
export class MintCounter extends OP_NET {
    private static readonly MINT_COST_SATS: u64 = 1420;
    private static readonly LEADERBOARD_MAX: u32 = 50;

    private readonly totalMintsPointer: u16 = Blockchain.nextPointer;
    private readonly endBlockPointer: u16 = Blockchain.nextPointer;
    private readonly treasuryPointer: u16 = Blockchain.nextPointer;
    private readonly userMintsPointer: u16 = Blockchain.nextPointer;
    private readonly allMintersPointer: u16 = Blockchain.nextPointer;
    private readonly totalUniqueMintersPointer: u16 = Blockchain.nextPointer;
    private readonly lbAddressesPointer: u16 = Blockchain.nextPointer;
    private readonly lbCountsPointer: u16 = Blockchain.nextPointer;
    private readonly lbSizePointer: u16 = Blockchain.nextPointer;

    private readonly _totalMints: StoredU256 = new StoredU256(
        this.totalMintsPointer,
        EMPTY_POINTER,
    );

    private readonly _endBlock: StoredU256 = new StoredU256(this.endBlockPointer, EMPTY_POINTER);

    private readonly _treasury: StoredString = new StoredString(this.treasuryPointer);

    private readonly _userMints: AddressMemoryMap = new AddressMemoryMap(this.userMintsPointer);

    private readonly _allMinters: StoredAddressArray = new StoredAddressArray(
        this.allMintersPointer,
        EMPTY_POINTER,
    );

    private readonly _totalUniqueMinters: StoredU256 = new StoredU256(
        this.totalUniqueMintersPointer,
        EMPTY_POINTER,
    );

    private readonly _lbAddresses: StoredAddressArray = new StoredAddressArray(
        this.lbAddressesPointer,
        EMPTY_POINTER,
    );

    private readonly _lbCounts: StoredU256Array = new StoredU256Array(
        this.lbCountsPointer,
        EMPTY_POINTER,
    );

    private readonly _lbSize: StoredU256 = new StoredU256(this.lbSizePointer, EMPTY_POINTER);

    public constructor() {
        super();
    }

    public override onDeployment(calldata: Calldata): void {
        const treasury: string = calldata.readStringWithLength();
        const endBlock: u256 = calldata.readU256();

        if (treasury.length === 0) {
            throw new Revert('Invalid treasury address');
        }

        if (endBlock.isZero()) {
            throw new Revert('Invalid end block');
        }

        if (endBlock <= Blockchain.block.numberU256) {
            throw new Revert('End block must be in the future');
        }

        this._treasury.value = treasury;
        this._endBlock.value = endBlock;
    }

    /**
     * Increment global + per-user mint counters.
     * Requires a >= 1,420 sat output to the treasury in the transaction.
     */
    @method()
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    @emit('MintCounter')
    @payable()
    public mint(_calldata: Calldata): BytesWriter {
        this.assertMintOpen();
        this.assertEOA();
        this.assertPayment(1);

        const sender: Address = Blockchain.tx.sender;

        const prevUserMints: u256 = this._userMints.get(sender);
        const isFirstMint: bool = prevUserMints.isZero();
        const newUserMints: u256 = SafeMath.add(prevUserMints, u256.One);
        this._userMints.set(sender, newUserMints);

        if (isFirstMint) {
            this.trackNewMinter(sender);
        }

        this.updateLeaderboard(sender, newUserMints);

        const newTotal: u256 = SafeMath.add(this._totalMints.value, u256.One);
        this._totalMints.value = newTotal;

        this.emitEvent(new MintCounterEvent(sender, newUserMints.toU64(), newTotal.toU64()));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Batch mint — increment counters by quantity in a single tx.
     * Requires >= (quantity * 1,420) sats output to treasury.
     */
    @method({ name: 'quantity', type: ABIDataTypes.UINT256 })
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    @emit('MintCounter')
    @payable()
    public batchMint(calldata: Calldata): BytesWriter {
        this.assertMintOpen();
        this.assertEOA();

        const quantity: u256 = calldata.readU256();
        if (quantity.isZero()) {
            throw new Revert('Quantity must be > 0');
        }

        const maxBatch: u256 = u256.fromU32(100);
        if (quantity > maxBatch) {
            throw new Revert('Max 100 mints per batch');
        }

        const quantityU64: u64 = quantity.toU64();
        this.assertPayment(quantityU64);

        const sender: Address = Blockchain.tx.sender;

        const prevUserMints: u256 = this._userMints.get(sender);
        const isFirstMint: bool = prevUserMints.isZero();
        const newUserMints: u256 = SafeMath.add(prevUserMints, quantity);
        this._userMints.set(sender, newUserMints);

        if (isFirstMint) {
            this.trackNewMinter(sender);
        }

        this.updateLeaderboard(sender, newUserMints);

        const newTotal: u256 = SafeMath.add(this._totalMints.value, quantity);
        this._totalMints.value = newTotal;

        this.emitEvent(new MintCounterEvent(sender, newUserMints.toU64(), newTotal.toU64()));

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    /**
     * Returns the mint count for a specific address.
     */
    @method({ name: 'account', type: ABIDataTypes.ADDRESS })
    @returns({ name: 'mints', type: ABIDataTypes.UINT256 })
    public getUserMints(calldata: Calldata): BytesWriter {
        const account: Address = calldata.readAddress();
        const count: u256 = this._userMints.get(account);
        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(count);
        return writer;
    }

    /**
     * Returns the global mint count.
     */
    @method()
    @returns({ name: 'mints', type: ABIDataTypes.UINT256 })
    public getTotalMints(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(this._totalMints.value);
        return writer;
    }

    /**
     * Returns the end block number.
     */
    @method()
    @returns({ name: 'endBlock', type: ABIDataTypes.UINT256 })
    public getEndBlock(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(this._endBlock.value);
        return writer;
    }

    /**
     * Returns the treasury Bitcoin address string.
     */
    @method()
    @returns({ name: 'treasury', type: ABIDataTypes.STRING })
    public getTreasury(_calldata: Calldata): BytesWriter {
        const val: string = this._treasury.value;
        const writer: BytesWriter = new BytesWriter(val.length + 4);
        writer.writeStringWithLength(val);
        return writer;
    }

    /**
     * Returns the fixed mint cost in satoshis (1,420).
     */
    @method()
    @returns({ name: 'cost', type: ABIDataTypes.UINT64 })
    public getMintCost(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(8);
        writer.writeU64(MintCounter.MINT_COST_SATS);
        return writer;
    }

    /**
     * Returns blocks remaining in the mint window (0 if ended).
     */
    @method()
    @returns({ name: 'remaining', type: ABIDataTypes.UINT256 })
    public getBlocksRemaining(_calldata: Calldata): BytesWriter {
        const endBlock: u256 = this._endBlock.value;
        const current: u256 = Blockchain.block.numberU256;
        let remaining: u256 = u256.Zero;

        if (endBlock > current) {
            remaining = SafeMath.sub(endBlock, current);
        }

        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(remaining);
        return writer;
    }

    /**
     * Returns a compact status snapshot.
     */
    @method()
    @returns(
        { name: 'totalMints', type: ABIDataTypes.UINT256 },
        { name: 'endBlock', type: ABIDataTypes.UINT256 },
        { name: 'blocksRemaining', type: ABIDataTypes.UINT256 },
        { name: 'treasury', type: ABIDataTypes.STRING },
        { name: 'mintCost', type: ABIDataTypes.UINT64 },
        { name: 'isEnded', type: ABIDataTypes.BOOL },
    )
    public getMintStatus(_calldata: Calldata): BytesWriter {
        const endBlock: u256 = this._endBlock.value;
        const current: u256 = Blockchain.block.numberU256;
        const isEnded: bool = current >= endBlock;

        let remaining: u256 = u256.Zero;
        if (!isEnded) {
            remaining = SafeMath.sub(endBlock, current);
        }

        const treasuryStr: string = this._treasury.value;
        const writer: BytesWriter = new BytesWriter(32 + 32 + 32 + treasuryStr.length + 4 + 8 + 1);
        writer.writeU256(this._totalMints.value);
        writer.writeU256(endBlock);
        writer.writeU256(remaining);
        writer.writeStringWithLength(treasuryStr);
        writer.writeU64(MintCounter.MINT_COST_SATS);
        writer.writeBoolean(isEnded);
        return writer;
    }

    /**
     * Returns the top leaderboard entries as a paginated ADDRESS_UINT256_TUPLE.
     *
     * Wire format: u32 totalEntries, u32 pageStart, u32 pageCount, then
     * u16 count prefix followed by (address 32b, u256 32b) pairs.
     *
     * The leaderboard is pre-sorted descending by mint count at write time,
     * so this read is O(pageSize) with zero sorting overhead.
     *
     * @param page   u256  — zero-based page index
     * @param limit  u256  — entries per page (clamped to 1..50)
     */
    @method(
        { name: 'page', type: ABIDataTypes.UINT256 },
        { name: 'limit', type: ABIDataTypes.UINT256 },
    )
    @returns(
        { name: 'totalEntries', type: ABIDataTypes.UINT32 },
        { name: 'pageStart', type: ABIDataTypes.UINT32 },
        { name: 'pageCount', type: ABIDataTypes.UINT32 },
        { name: 'entries', type: ABIDataTypes.ADDRESS_UINT256_TUPLE },
    )
    public getLeaderboard(calldata: Calldata): BytesWriter {
        const pageRaw: u256 = calldata.readU256();
        const limitRaw: u256 = calldata.readU256();

        const lbSize: u32 = this._lbSize.value.toU32();

        let limit: u32 = limitRaw.toU32();
        if (limit == 0) {
            limit = 10;
        }

        if (limit > 50) {
            limit = 50;
        }

        const page: u32 = pageRaw.toU32();
        const startIndex: u32 = page * limit;

        let pageCount: u32 = 0;

        // Pre-calculate the buffer size: 4 + 4 + 4 + 2 (tuple count prefix) + pageCount * 64
        // We compute pageCount first to size the buffer correctly.
        if (startIndex < lbSize) {
            const remaining: u32 = lbSize - startIndex;
            pageCount = remaining < limit ? remaining : limit;
        }

        const bufSize: u32 = 4 + 4 + 4 + 2 + pageCount * 64;
        const writer: BytesWriter = new BytesWriter(bufSize);

        writer.writeU32(lbSize);
        writer.writeU32(startIndex);
        writer.writeU32(pageCount);

        // Write ADDRESS_UINT256_TUPLE wire format: u16 count, then entries
        writer.writeU16(<u16>pageCount);

        for (let i: u32 = 0; i < pageCount; i++) {
            const idx: u32 = startIndex + i;
            const addr: Address = this._lbAddresses.get(idx);
            const count: u256 = this._lbCounts.get(idx);
            writer.writeAddress(addr);
            writer.writeU256(count);
        }

        return writer;
    }

    /**
     * Returns a paginated list of ALL unique minters (unsorted, insertion order).
     * Useful for off-chain indexing or full enumeration via repeated RPC calls.
     *
     * @param page   u256  — zero-based page index
     * @param limit  u256  — entries per page (clamped to 1..50)
     */
    @method(
        { name: 'page', type: ABIDataTypes.UINT256 },
        { name: 'limit', type: ABIDataTypes.UINT256 },
    )
    @returns(
        { name: 'totalEntries', type: ABIDataTypes.UINT32 },
        { name: 'pageStart', type: ABIDataTypes.UINT32 },
        { name: 'pageCount', type: ABIDataTypes.UINT32 },
        { name: 'entries', type: ABIDataTypes.ADDRESS_UINT256_TUPLE },
    )
    public getAllMinters(calldata: Calldata): BytesWriter {
        const pageRaw: u256 = calldata.readU256();
        const limitRaw: u256 = calldata.readU256();

        const totalMinters: u32 = this._totalUniqueMinters.value.toU32();

        let limit: u32 = limitRaw.toU32();
        if (limit == 0) {
            limit = 10;
        }
        if (limit > 50) {
            limit = 50;
        }

        const page: u32 = pageRaw.toU32();
        const startIndex: u32 = page * limit;

        let pageCount: u32 = 0;
        if (startIndex < totalMinters) {
            const remaining: u32 = totalMinters - startIndex;
            pageCount = remaining < limit ? remaining : limit;
        }

        const bufSize: u32 = 4 + 4 + 4 + 2 + pageCount * 64;
        const writer: BytesWriter = new BytesWriter(bufSize);

        writer.writeU32(totalMinters);
        writer.writeU32(startIndex);
        writer.writeU32(pageCount);

        // Write ADDRESS_UINT256_TUPLE: u16 count, then (address, mintCount) pairs
        writer.writeU16(<u16>pageCount);

        for (let i: u32 = 0; i < pageCount; i++) {
            const idx: u32 = startIndex + i;
            const addr: Address = this._allMinters.get(idx);
            const count: u256 = this._userMints.get(addr);
            writer.writeAddress(addr);
            writer.writeU256(count);
        }

        return writer;
    }

    /**
     * Returns the total number of unique minters.
     */
    @method()
    @returns({ name: 'total', type: ABIDataTypes.UINT256 })
    public getTotalUniqueMinters(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(32);
        writer.writeU256(this._totalUniqueMinters.value);
        return writer;
    }

    /**
     * Append a first-time minter to the all-minters array and bump the unique count.
     */
    private trackNewMinter(sender: Address): void {
        this._allMinters.push(sender);
        this._allMinters.save();

        const prev: u256 = this._totalUniqueMinters.value;
        this._totalUniqueMinters.value = SafeMath.add(prev, u256.One);
    }

    /**
     * Maintain the top-50 leaderboard in descending order by mint count.
     *
     * Algorithm:
     *   1. If the sender is already in the leaderboard, find their current index.
     *      Remove them from that position (shift everything below up by one).
     *   2. Binary-search for the correct insertion point for newCount in the
     *      descending-sorted array.
     *   3. If the insertion point is within the max size (50), insert there,
     *      shifting entries down. If the array was already at max size and the
     *      new entry displaced the tail, the tail is simply overwritten by the shift.
     *
     * Worst case: ~50 storage reads to scan for existing entry + ~50 shifts.
     * In practice, most updates are for users already near the top, so the scan
     * and shift distances are short.
     */
    private updateLeaderboard(sender: Address, newCount: u256): void {
        const currentSize: u32 = this._lbSize.value.toU32();
        const maxSize: u32 = MintCounter.LEADERBOARD_MAX;

        // Step 1: Find existing index (-1 if not present)
        let existingIdx: i32 = -1;
        for (let i: u32 = 0; i < currentSize; i++) {
            if (this._lbAddresses.get(i).equals(sender)) {
                existingIdx = <i32>i;
                break;
            }
        }

        // Step 2: If the sender is not in the leaderboard and the board is full,
        // check if newCount beats the last entry. If not, nothing to do.
        if (existingIdx == -1 && currentSize >= maxSize) {
            const lastCount: u256 = this._lbCounts.get(maxSize - 1);
            if (newCount <= lastCount) {
                return;
            }
        }

        // Step 3: Remove existing entry by shifting everything after it up
        let workingSize: u32 = currentSize;
        if (existingIdx >= 0) {
            const eidx: u32 = <u32>existingIdx;
            for (let i: u32 = eidx; i < workingSize - 1; i++) {
                this._lbAddresses.set(i, this._lbAddresses.get(i + 1));
                this._lbCounts.set(i, this._lbCounts.get(i + 1));
            }
            workingSize -= 1;
        }

        // Step 4: Binary search for insertion point in descending order
        let lo: u32 = 0;
        let hi: u32 = workingSize;
        while (lo < hi) {
            const mid: u32 = lo + ((hi - lo) >> 1);
            const midCount: u256 = this._lbCounts.get(mid);
            if (midCount >= newCount) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        const insertAt: u32 = lo;

        // Step 5: If insertion point is beyond max size, nothing to insert
        if (insertAt >= maxSize) {
            // Persist the removal if we removed an existing entry
            if (existingIdx >= 0) {
                this._lbAddresses.save();
                this._lbCounts.save();
                this._lbSize.value = u256.fromU32(workingSize);
            }
            return;
        }

        // Step 6: Determine new size after insertion
        let newSize: u32 = workingSize + 1;
        if (newSize > maxSize) {
            newSize = maxSize;
        }

        // Step 7: Shift entries down from insertAt to make room
        // We shift from the end to avoid overwriting. The last valid index is newSize - 1.
        // If newSize == workingSize + 1, we shift all entries from insertAt..workingSize-1.
        // If newSize == maxSize and workingSize was already maxSize, the last entry is dropped.
        if (newSize > insertAt + 1) {
            const shiftEnd: u32 = newSize - 1;
            // Shift down: move entries from [insertAt, shiftEnd-1] to [insertAt+1, shiftEnd]
            let j: u32 = shiftEnd;
            while (j > insertAt) {
                this._lbAddresses.set(j, this._lbAddresses.get(j - 1));
                this._lbCounts.set(j, this._lbCounts.get(j - 1));
                j -= 1;
            }
        }

        // Step 8: Write the new entry at insertAt
        this._lbAddresses.set(insertAt, sender);
        this._lbCounts.set(insertAt, newCount);

        this._lbAddresses.save();
        this._lbCounts.save();
        this._lbSize.value = u256.fromU32(newSize);
    }

    private assertMintOpen(): void {
        if (this._endBlock.value.isZero()) {
            throw new Revert('Contract not initialized');
        }

        if (Blockchain.block.numberU256 >= this._endBlock.value) {
            throw new Revert('Mint ended');
        }
    }

    private assertEOA(): void {
        if (!Blockchain.tx.sender.equals(Blockchain.tx.origin)) {
            throw new Revert('Only EOA wallets');
        }
    }

    private assertPayment(amount: u64): void {
        const treasury: string = this._treasury.value;
        const txOutputs = Blockchain.tx.outputs;
        const len: i32 = txOutputs.length;

        for (let i: i32 = 0; i < len; i++) {
            const out = txOutputs[i];
            if (
                out.to !== null &&
                out.value >= MintCounter.MINT_COST_SATS * amount &&
                out.to === treasury
            ) {
                return;
            }
        }

        throw new Revert('Payment required: 1420 sats to treasury');
    }
}
