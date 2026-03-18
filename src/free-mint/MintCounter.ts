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
    StoredString,
    StoredU256,
} from '@btc-vision/btc-runtime/runtime';
import { MintCounterEvent } from './events/MintCounterEvent';

/**
 * MintCounter
 *
 * Tracks global and per-user mint counts for the PILL free-mint event.
 * Each call to mint() must include a >= 1,420 sat output to the treasury address.
 * No per-address cap. Minting closes when currentBlock >= endBlock.
 *
 * Deployment calldata:
 *   treasury  string  — Bitcoin P2TR address receiving 1,420 sats per mint
 *   endBlock  u256    — block height at which minting closes (exclusive)
 */
@final
export class MintCounter extends OP_NET {
    private static readonly MINT_COST_SATS: u64 = 1420;

    private readonly totalMintsPointer: u16 = Blockchain.nextPointer;
    private readonly endBlockPointer: u16 = Blockchain.nextPointer;
    private readonly treasuryPointer: u16 = Blockchain.nextPointer;
    private readonly userMintsPointer: u16 = Blockchain.nextPointer;

    private readonly _totalMints: StoredU256 = new StoredU256(
        this.totalMintsPointer,
        EMPTY_POINTER,
    );

    private readonly _endBlock: StoredU256 = new StoredU256(this.endBlockPointer, EMPTY_POINTER);

    private readonly _treasury: StoredString = new StoredString(this.treasuryPointer);

    private readonly _userMints: AddressMemoryMap = new AddressMemoryMap(this.userMintsPointer);

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
        const newUserMints: u256 = SafeMath.add(prevUserMints, u256.One);
        this._userMints.set(sender, newUserMints);

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
        const newUserMints: u256 = SafeMath.add(prevUserMints, quantity);
        this._userMints.set(sender, newUserMints);

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
     * Returns a compact status snapshot:
     *   totalMints      u256
     *   endBlock        u256
     *   blocksRemaining u256
     *   treasury        Address (32 bytes)
     *   mintCost        u64
     *   isEnded         bool
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
