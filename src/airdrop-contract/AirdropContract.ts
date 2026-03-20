import {
    Address,
    ADDRESS_BYTE_LENGTH,
    AddressMemoryMap,
    Blockchain,
    BytesWriter,
    Calldata,
    encodeSelector,
    ON_OP20_RECEIVED_SELECTOR,
    OP_NET,
    Revert,
    SafeMath,
    SELECTOR_BYTE_LENGTH,
    StoredBoolean,
    StoredU64,
    TransferHelper,
    U256_BYTE_LENGTH,
} from '@btc-vision/btc-runtime/runtime';
import { u256 } from '@btc-vision/as-bignum/assembly';

const MOTO_ADDRESS: Uint8Array = new Uint8Array(32);
MOTO_ADDRESS.set([]);

const PILL_ADDRESS: Uint8Array = new Uint8Array(32);
PILL_ADDRESS.set([]);

const MOTO_SCALE: u256 = u256.fromString('10000000000000000');
const PILL_SCALE: u256 = u256.fromString('1000000000000000000');

@final
export class AirdropContract extends OP_NET {
    private static readonly BLOCK_SUB: Uint8Array = new Uint8Array(30);

    private readonly blockPointer: u16 = Blockchain.nextPointer;
    private readonly pausedPointer: u16 = Blockchain.nextPointer;

    private readonly allocationsPointerPill: u16 = Blockchain.nextPointer;
    private readonly allocationsPointerMoto: u16 = Blockchain.nextPointer;
    private readonly redeemedPointer: u16 = Blockchain.nextPointer;

    private readonly MOTO_ADDRESS: Address = Address.fromUint8Array(MOTO_ADDRESS);
    private readonly PILL_ADDRESS: Address = Address.fromUint8Array(PILL_ADDRESS);

    private readonly blockData: StoredU64 = new StoredU64(
        this.blockPointer,
        AirdropContract.BLOCK_SUB,
    );

    private readonly paused: StoredBoolean = new StoredBoolean(this.pausedPointer, false);

    private readonly allocationsPill: AddressMemoryMap = new AddressMemoryMap(
        this.allocationsPointerPill,
    );

    private readonly allocationsMoto: AddressMemoryMap = new AddressMemoryMap(
        this.allocationsPointerMoto,
    );

    private readonly holders: AddressMemoryMap = new AddressMemoryMap(this.redeemedPointer);

    public constructor() {
        super();
    }

    public override onDeployment(calldata: Calldata): void {
        const delayBlocks: u64 = calldata.readU64();
        const durationBlocks: u64 = calldata.readU64();
        const durationBlocksPill: u64 = calldata.readU64();

        const open: u64 = Blockchain.block.number + delayBlocks;
        const closeMoto: u64 = open + durationBlocks;
        const closePill: u64 = open + durationBlocksPill;

        this.blockData.set(0, open);
        this.blockData.set(1, closeMoto);
        this.blockData.set(2, closePill);

        this.paused.value = true;

        this.blockData.save();
    }

    @method()
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public claim(_calldata: Calldata): BytesWriter {
        if (Blockchain.tx.sender !== Blockchain.tx.origin) {
            throw new Revert(`Only users may call this.`);
        }

        if (this.paused.value) {
            throw new Revert('Airdrop: paused');
        }

        const open: u64 = this.blockData.get(0);
        const closeMoto: u64 = this.blockData.get(1);
        const closePill: u64 = this.blockData.get(2);
        const current: u64 = Blockchain.block.number;

        if (current < open || current > closeMoto) {
            throw new Revert('Airdrop: not active');
        }

        const publicKey = Address.fromUint8Array(Blockchain.tx.origin.tweakedPublicKey);
        const redeemed: bool = this.holders.has(publicKey);
        if (redeemed) {
            throw new Revert('Airdrop: redeemed');
        }

        const redeemedValue = this.holders.get(publicKey);
        if (redeemedValue === u256.One) {
            throw new Revert('Airdrop: redeemed');
        }

        const allocationPill: bool = this.allocationsPill.has(publicKey);
        const allocationMoto: bool = this.allocationsMoto.has(publicKey);

        if (!allocationPill && !allocationMoto) {
            throw new Revert('Airdrop: no allocation');
        }

        this.holders.set(publicKey, u256.One);

        if (allocationPill && current <= closePill) {
            this.distributePill(publicKey);
        }

        if (allocationMoto) {
            this.distributeMoto(publicKey);
        }

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    @method()
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public pause(_calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        this.paused.value = true;

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    @method()
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public unpause(_calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        this.paused.value = false;

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    @method(
        { name: 'operator', type: ABIDataTypes.ADDRESS },
        { name: 'from', type: ABIDataTypes.ADDRESS },
        { name: 'amount', type: ABIDataTypes.UINT256 },
        { name: 'data', type: ABIDataTypes.BYTES },
    )
    @returns({ name: 'selector', type: ABIDataTypes.BYTES4 })
    public onOP20Received(_calldata: Calldata): BytesWriter {
        const w = new BytesWriter(SELECTOR_BYTE_LENGTH);
        w.writeSelector(ON_OP20_RECEIVED_SELECTOR);

        return w;
    }

    @method()
    @returns(
        {
            name: 'canClaimPill',
            type: ABIDataTypes.BOOL,
        },
        {
            name: 'canClaimMoto',
            type: ABIDataTypes.BOOL,
        },
        {
            name: 'claimablePill',
            type: ABIDataTypes.UINT256,
        },
        {
            name: 'claimableMoto',
            type: ABIDataTypes.UINT256,
        },
    )
    @view()
    public claimed(): BytesWriter {
        const open: u64 = this.blockData.get(0);
        const closeMoto: u64 = this.blockData.get(1);
        const closePill: u64 = this.blockData.get(2);
        const current: u64 = Blockchain.block.number;

        if (current < open || current > closeMoto) {
            throw new Revert('Airdrop: not active');
        }

        const publicKey = Address.fromUint8Array(Blockchain.tx.origin.tweakedPublicKey);
        const redeemed: bool = this.holders.has(publicKey);
        if (redeemed) {
            throw new Revert('Airdrop: redeemed');
        }

        const redeemedValue = this.holders.get(publicKey);
        if (redeemedValue === u256.One) {
            throw new Revert('Airdrop: redeemed');
        }

        const allocationPill: bool = this.allocationsPill.has(publicKey);
        const allocationMoto: bool = this.allocationsMoto.has(publicKey);
        if (!allocationPill && !allocationMoto) {
            throw new Revert('Airdrop: no allocation');
        }

        const writer: BytesWriter = new BytesWriter(2 + U256_BYTE_LENGTH * 2);
        writer.writeBoolean(<boolean>(allocationPill && current <= closePill));
        writer.writeBoolean(<boolean>allocationMoto);
        writer.writeU256(SafeMath.mul(this.allocationsPill.get(publicKey), PILL_SCALE));
        writer.writeU256(SafeMath.mul(this.allocationsMoto.get(publicKey), MOTO_SCALE));

        return writer;
    }

    @method(
        { name: 'addresses', type: ABIDataTypes.ARRAY_OF_ADDRESSES },
        { name: 'motoAmounts', type: ABIDataTypes.ARRAY_OF_UINT32 },
        { name: 'pillAmounts', type: ABIDataTypes.ARRAY_OF_UINT32 },
    )
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public airdrop(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const addresses: Address[] = calldata.readAddressArray();
        const motoAmounts: u32[] = calldata.readU32Array();
        const pillAmounts: u32[] = calldata.readU32Array();

        const len: i32 = addresses.length;
        if (len !== motoAmounts.length || len !== pillAmounts.length) {
            throw new Revert('Airdrop: length mismatch');
        }

        for (let i: i32 = 0; i < len; i++) {
            const addr: Address = addresses[i];
            const moto: u32 = unchecked(motoAmounts[i]);
            const pill: u32 = unchecked(pillAmounts[i]);

            if (moto > 0) {
                this.allocationsMoto.set(addr, u256.fromU32(moto));
            }

            if (pill > 0) {
                this.allocationsPill.set(addr, u256.fromU32(pill));
            }
        }

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    @method()
    @returns({ name: 'success', type: ABIDataTypes.BOOL })
    public withdraw(_calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.origin);

        const motoBalance: u256 = this.queryBalance(this.MOTO_ADDRESS);
        if (!motoBalance.isZero()) {
            TransferHelper.transfer(this.MOTO_ADDRESS, Blockchain.tx.origin, motoBalance);
        }

        const pillBalance: u256 = this.queryBalance(this.PILL_ADDRESS);
        if (!pillBalance.isZero()) {
            TransferHelper.transfer(this.PILL_ADDRESS, Blockchain.tx.origin, pillBalance);
        }

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(true);
        return writer;
    }

    private queryBalance(token: Address): u256 {
        const calldata = new BytesWriter(SELECTOR_BYTE_LENGTH + ADDRESS_BYTE_LENGTH);
        calldata.writeSelector(encodeSelector('balanceOf(address)'));
        calldata.writeAddress(this.address);

        const response = Blockchain.call(token, calldata);
        return response.data.readU256();
    }

    private distributePill(publicKey: Address): void {
        const raw: u256 = this.allocationsPill.get(publicKey);
        if (raw.isZero()) return;

        const currentBalance = this.queryBalance(this.PILL_ADDRESS);
        if (currentBalance.isZero()) {
            throw new Revert('Airdrop: pill empty');
        }

        this.allocationsPill.delete(publicKey);

        const amount: u256 = SafeMath.mul(raw, PILL_SCALE);
        if (amount > currentBalance) {
            throw new Revert(`Airdrop: pill insufficient balance ${amount} > ${currentBalance}`);
        }

        TransferHelper.transfer(this.PILL_ADDRESS, Blockchain.tx.origin, amount);
    }

    private distributeMoto(publicKey: Address): void {
        const raw: u256 = this.allocationsMoto.get(publicKey);
        if (raw.isZero()) return;

        const currentBalance = this.queryBalance(this.MOTO_ADDRESS);
        if (currentBalance.isZero()) {
            throw new Revert('Airdrop: distributeMoto empty');
        }

        this.allocationsMoto.delete(publicKey);

        const amount: u256 = SafeMath.mul(raw, MOTO_SCALE);
        if (amount > currentBalance) {
            throw new Revert(
                `Airdrop: distributeMoto insufficient balance ${amount} > ${currentBalance}`,
            );
        }

        TransferHelper.transfer(this.MOTO_ADDRESS, Blockchain.tx.origin, amount);
    }
}
