import { createHash } from 'crypto';
import { Address, BinaryWriter, BinaryReader, MessageSigner, AddressMap } from '@btc-vision/transaction';
import { networks } from '@btc-vision/bitcoin';
import {
    opnet,
    OPNetUnit,
    Assert,
    Blockchain,
    BytecodeManager,
    ContractRuntime,
    CallResponse,
    OP20,
} from '@btc-vision/unit-test-framework';

// Use OPNet testnet
Blockchain.changeNetwork(networks.opnetTestnet);

// ============================================================================
// AirdropRuntime: wrapper for the distributor contract
// ============================================================================

class AirdropRuntime extends ContractRuntime {
    private readonly airdropSelector: number = this.getSelector('airdrop(tuple(address,uint256)[],tuple(address,uint256)[])');
    private readonly claimSelector: number = this.getSelector('claim(bytes)');
    private readonly pauseSelector: number = this.getSelector('pause()');
    private readonly unpauseSelector: number = this.getSelector('unpause()');
    private readonly infoSelector: number = this.getSelector('info()');
    private readonly allocationSelector: number = this.getSelector('allocation(address)');

    public constructor(
        deployer: Address,
        address: Address,
        deploymentCalldata?: Buffer,
        gasLimit: bigint = 500_000_000_000n,
    ) {
        super({ address, deployer, gasLimit, deploymentCalldata });
    }

    public async airdrop(
        pillAllocs: AddressMap<bigint>,
        motoAllocs: AddressMap<bigint>,
    ): Promise<CallResponse> {
        const cd = new BinaryWriter();
        cd.writeSelector(this.airdropSelector);
        cd.writeAddressValueTuple(pillAllocs);
        cd.writeAddressValueTuple(motoAllocs);
        return await this.execute({ calldata: cd.getBuffer() });
    }

    public async claim(signature: Uint8Array): Promise<CallResponse> {
        const cd = new BinaryWriter();
        cd.writeSelector(this.claimSelector);
        cd.writeBytesWithLength(signature);
        return await this.execute({ calldata: cd.getBuffer() });
    }

    public async pause(): Promise<CallResponse> {
        const cd = new BinaryWriter();
        cd.writeSelector(this.pauseSelector);
        return await this.execute({ calldata: cd.getBuffer() });
    }

    public async unpause(): Promise<CallResponse> {
        const cd = new BinaryWriter();
        cd.writeSelector(this.unpauseSelector);
        return await this.execute({ calldata: cd.getBuffer() });
    }

    public async info(): Promise<{
        pillEndBlock: bigint;
        motoEndBlock: bigint;
        startBlock: bigint;
        paused: boolean;
    }> {
        const cd = new BinaryWriter();
        cd.writeSelector(this.infoSelector);
        const resp = await this.execute({ calldata: cd.getBuffer() });
        if (resp.error) throw resp.error;
        const r = new BinaryReader(resp.response);
        return {
            pillEndBlock: r.readU64(),
            motoEndBlock: r.readU64(),
            startBlock: r.readU64(),
            paused: r.readBoolean(),
        };
    }

    public async allocation(user: Address): Promise<{
        pillAllocation: bigint;
        motoAllocation: bigint;
        hasClaimed: boolean;
    }> {
        const cd = new BinaryWriter();
        cd.writeSelector(this.allocationSelector);
        cd.writeAddress(user);
        const resp = await this.execute({ calldata: cd.getBuffer() });
        if (resp.error) throw resp.error;
        const r = new BinaryReader(resp.response);
        return {
            pillAllocation: r.readU256(),
            motoAllocation: r.readU256(),
            hasClaimed: r.readBoolean(),
        };
    }

    protected handleError(error: Error): Error {
        return new Error(`(AirdropDistributor: ${this.address}) ${error.message}`);
    }

    protected defineRequiredBytecodes(): void {
        BytecodeManager.loadBytecode('./bytecodes/AirdropToken.wasm', this.address);
    }

    private getSelector(sig: string): number {
        return Number(`0x${this.abiCoder.encodeSelector(sig)}`);
    }
}

// ============================================================================
// Helpers
// ============================================================================

const PILL_DURATION = 1008n;  // ~7 days at 10 min/block
const MOTO_DURATION = 4320n;  // ~30 days at 10 min/block

function buildDeployCalldata(
    pillAddress: Address,
    motoAddress: Address,
    pillDuration: bigint = PILL_DURATION,
    motoDuration: bigint = MOTO_DURATION,
): Buffer {
    const w = new BinaryWriter();
    w.writeAddress(pillAddress);
    w.writeAddress(motoAddress);
    w.writeU64(pillDuration);
    w.writeU64(motoDuration);
    return Buffer.from(w.getBuffer());
}

function buildClaimMessage(sender: Address, contractAddress: Address): Uint8Array {
    const prefix = Buffer.from('airdrop:', 'utf-8');
    const msg = new Uint8Array(prefix.length + 32 + 32);
    msg.set(prefix, 0);
    for (let i = 0; i < 32; i++) msg[prefix.length + i] = sender[i];
    for (let i = 0; i < 32; i++) msg[prefix.length + 32 + i] = contractAddress[i];
    return msg;
}

function signClaim(
    wallet: ReturnType<typeof Blockchain.generateRandomWallet>,
    contractAddress: Address,
): Uint8Array {
    const raw = buildClaimMessage(wallet.address, contractAddress);
    return MessageSigner.tweakAndSignMessage(wallet.keypair, raw, Blockchain.network).signature;
}

// ============================================================================
// Tests
// ============================================================================

await opnet('AirdropDistributor Tests', async (vm: OPNetUnit) => {
    let distributor: AirdropRuntime;
    let pill: OP20;
    let moto: OP20;

    const deployer = Blockchain.generateRandomAddress();
    const distributorAddress = Blockchain.generateRandomAddress();
    const pillAddress = Blockchain.generateRandomAddress();
    const motoAddress = Blockchain.generateRandomAddress();

    const PILL_AMOUNT = 1000n * (10n ** 18n);
    const MOTO_AMOUNT = 500n * (10n ** 18n);

    vm.beforeEach(async () => {
        Blockchain.dispose();
        Blockchain.clearContracts();
        await Blockchain.init();

        Blockchain.blockNumber = 10n;
        Blockchain.txOrigin = deployer;
        Blockchain.msgSender = deployer;

        // Deploy PILL token
        pill = new OP20({
            address: pillAddress,
            deployer: deployer,
            file: './bytecodes/MyToken.wasm',
            decimals: 18,
        });
        Blockchain.register(pill);
        await pill.init();

        // Deploy MOTO token
        moto = new OP20({
            address: motoAddress,
            deployer: deployer,
            file: './bytecodes/MyToken.wasm',
            decimals: 18,
        });
        Blockchain.register(moto);
        await moto.init();

        // Deploy distributor
        const deployData = buildDeployCalldata(pillAddress, motoAddress);
        distributor = new AirdropRuntime(deployer, distributorAddress, deployData);
        Blockchain.register(distributor);
        await distributor.init();

        // Mint tokens to the distributor contract so it can transfer
        Blockchain.msgSender = deployer;
        Blockchain.txOrigin = deployer;
        await pill.mintRaw(distributorAddress, PILL_AMOUNT * 100n);
        await moto.mintRaw(distributorAddress, MOTO_AMOUNT * 100n);
    });

    vm.afterEach(() => {
        distributor.dispose();
        pill.dispose();
        moto.dispose();
        Blockchain.dispose();
    });

    // 1. Deploy config
    await vm.it('should deploy with correct config', async () => {
        const i = await distributor.info();
        Assert.expect(i.startBlock).toEqual(10n);
        Assert.expect(i.pillEndBlock).toEqual(10n + PILL_DURATION);
        Assert.expect(i.motoEndBlock).toEqual(10n + MOTO_DURATION);
        Assert.expect(i.paused).toEqual(false);
        vm.success(`PILL ends block ${i.pillEndBlock}, MOTO ends block ${i.motoEndBlock}`);
    });

    // 2. Owner sets allocations
    await vm.it('should allow owner to set allocations via airdrop()', async () => {
        const user = Blockchain.generateRandomAddress();

        const pillMap = new AddressMap<bigint>();
        pillMap.set(user, PILL_AMOUNT);
        const motoMap = new AddressMap<bigint>();
        motoMap.set(user, MOTO_AMOUNT);

        Blockchain.txOrigin = deployer;
        Blockchain.msgSender = deployer;

        const resp = await distributor.airdrop(pillMap, motoMap);
        Assert.expect(resp.error).toBeUndefined();

        const alloc = await distributor.allocation(user);
        Assert.expect(alloc.pillAllocation).toEqual(PILL_AMOUNT);
        Assert.expect(alloc.motoAllocation).toEqual(MOTO_AMOUNT);
        Assert.expect(alloc.hasClaimed).toEqual(false);
        vm.success('Allocations set');
    });

    // 3. User claims both PILL and MOTO
    await vm.it('should transfer PILL and MOTO on valid claim', async () => {
        const wallet = Blockchain.generateRandomWallet();

        // Set allocations
        const pillMap = new AddressMap<bigint>();
        pillMap.set(wallet.address, PILL_AMOUNT);
        const motoMap = new AddressMap<bigint>();
        motoMap.set(wallet.address, MOTO_AMOUNT);

        Blockchain.txOrigin = deployer;
        Blockchain.msgSender = deployer;
        await distributor.airdrop(pillMap, motoMap);

        // Claim
        Blockchain.txOrigin = wallet.address;
        Blockchain.msgSender = wallet.address;
        const sig = signClaim(wallet, distributorAddress);
        const resp = await distributor.claim(sig);
        Assert.expect(resp.error).toBeUndefined();

        // Check balances
        const pillBal = await pill.balanceOf(wallet.address);
        const motoBal = await moto.balanceOf(wallet.address);
        Assert.expect(pillBal).toEqual(PILL_AMOUNT);
        Assert.expect(motoBal).toEqual(MOTO_AMOUNT);
        vm.success(`PILL: ${pillBal}, MOTO: ${motoBal}`);
    });

    // 4. Double claim rejected
    await vm.it('should reject double claim', async () => {
        const wallet = Blockchain.generateRandomWallet();

        const pillMap = new AddressMap<bigint>();
        pillMap.set(wallet.address, PILL_AMOUNT);
        const motoMap = new AddressMap<bigint>();
        motoMap.set(wallet.address, MOTO_AMOUNT);

        Blockchain.txOrigin = deployer;
        Blockchain.msgSender = deployer;
        await distributor.airdrop(pillMap, motoMap);

        Blockchain.txOrigin = wallet.address;
        Blockchain.msgSender = wallet.address;
        const sig = signClaim(wallet, distributorAddress);

        const first = await distributor.claim(sig);
        Assert.expect(first.error).toBeUndefined();

        const sig2 = signClaim(wallet, distributorAddress);
        const second = await distributor.claim(sig2);
        Assert.expect(second.error).toBeDefined();
        vm.success('Double claim rejected');
    });

    // 5. No allocation = rejected
    await vm.it('should reject claim with no allocation', async () => {
        const wallet = Blockchain.generateRandomWallet();
        Blockchain.txOrigin = wallet.address;
        Blockchain.msgSender = wallet.address;

        const sig = signClaim(wallet, distributorAddress);
        const resp = await distributor.claim(sig);
        Assert.expect(resp.error).toBeDefined();
        vm.success('No allocation rejected');
    });

    // 6. Non-owner cannot call airdrop()
    await vm.it('should reject airdrop() from non-owner', async () => {
        const rando = Blockchain.generateRandomWallet();
        Blockchain.txOrigin = rando.address;
        Blockchain.msgSender = rando.address;

        const pillMap = new AddressMap<bigint>();
        const motoMap = new AddressMap<bigint>();

        const resp = await distributor.airdrop(pillMap, motoMap);
        Assert.expect(resp.error).toBeDefined();
        vm.success('Non-owner airdrop rejected');
    });

    // 7. Paused claim rejected
    await vm.it('should reject claim when paused', async () => {
        const wallet = Blockchain.generateRandomWallet();

        const pillMap = new AddressMap<bigint>();
        pillMap.set(wallet.address, PILL_AMOUNT);
        const motoMap = new AddressMap<bigint>();
        motoMap.set(wallet.address, MOTO_AMOUNT);

        Blockchain.txOrigin = deployer;
        Blockchain.msgSender = deployer;
        await distributor.airdrop(pillMap, motoMap);
        await distributor.pause();

        Blockchain.txOrigin = wallet.address;
        Blockchain.msgSender = wallet.address;
        const sig = signClaim(wallet, distributorAddress);
        const resp = await distributor.claim(sig);
        Assert.expect(resp.error).toBeDefined();
        vm.success('Paused claim rejected');
    });

    // 8. Invalid signature rejected
    await vm.it('should reject invalid signature', async () => {
        const wallet = Blockchain.generateRandomWallet();

        const pillMap = new AddressMap<bigint>();
        pillMap.set(wallet.address, PILL_AMOUNT);
        const motoMap = new AddressMap<bigint>();

        Blockchain.txOrigin = deployer;
        Blockchain.msgSender = deployer;
        await distributor.airdrop(pillMap, motoMap);

        Blockchain.txOrigin = wallet.address;
        Blockchain.msgSender = wallet.address;
        const badSig = new Uint8Array(64);
        const resp = await distributor.claim(badSig);
        Assert.expect(resp.error).toBeDefined();
        vm.success('Bad signature rejected');
    });

    // 9. Pause/unpause by non-deployer rejected
    await vm.it('should reject pause/unpause from non-deployer', async () => {
        const rando = Blockchain.generateRandomWallet();
        Blockchain.txOrigin = rando.address;
        Blockchain.msgSender = rando.address;

        const p = await distributor.pause();
        Assert.expect(p.error).toBeDefined();

        const u = await distributor.unpause();
        Assert.expect(u.error).toBeDefined();
        vm.success('Non-deployer pause/unpause rejected');
    });

    // 10. Deployer pause/unpause works
    await vm.it('should allow deployer to pause and unpause', async () => {
        Blockchain.txOrigin = deployer;
        Blockchain.msgSender = deployer;

        const p = await distributor.pause();
        Assert.expect(p.error).toBeUndefined();
        Assert.expect((await distributor.info()).paused).toEqual(true);

        const u = await distributor.unpause();
        Assert.expect(u.error).toBeUndefined();
        Assert.expect((await distributor.info()).paused).toEqual(false);
        vm.success('Pause/unpause works');
    });

    // 11. Allocation query works
    await vm.it('should return correct allocation and claimed status', async () => {
        const wallet = Blockchain.generateRandomWallet();

        const pillMap = new AddressMap<bigint>();
        pillMap.set(wallet.address, PILL_AMOUNT);
        const motoMap = new AddressMap<bigint>();
        motoMap.set(wallet.address, MOTO_AMOUNT);

        Blockchain.txOrigin = deployer;
        Blockchain.msgSender = deployer;
        await distributor.airdrop(pillMap, motoMap);

        const before = await distributor.allocation(wallet.address);
        Assert.expect(before.hasClaimed).toEqual(false);
        Assert.expect(before.pillAllocation).toEqual(PILL_AMOUNT);

        // Claim
        Blockchain.txOrigin = wallet.address;
        Blockchain.msgSender = wallet.address;
        const sig = signClaim(wallet, distributorAddress);
        await distributor.claim(sig);

        const after = await distributor.allocation(wallet.address);
        Assert.expect(after.hasClaimed).toEqual(true);
        Assert.expect(after.pillAllocation).toEqual(0n);
        Assert.expect(after.motoAllocation).toEqual(0n);
        vm.success('Allocation query correct');
    });

    // 12. Multiple users can claim
    await vm.it('should allow 3 different users to claim', async () => {
        const wallets = [
            Blockchain.generateRandomWallet(),
            Blockchain.generateRandomWallet(),
            Blockchain.generateRandomWallet(),
        ];

        const pillMap = new AddressMap<bigint>();
        const motoMap = new AddressMap<bigint>();
        for (const w of wallets) {
            pillMap.set(w.address, PILL_AMOUNT);
            motoMap.set(w.address, MOTO_AMOUNT);
        }

        Blockchain.txOrigin = deployer;
        Blockchain.msgSender = deployer;
        await distributor.airdrop(pillMap, motoMap);

        for (const w of wallets) {
            Blockchain.txOrigin = w.address;
            Blockchain.msgSender = w.address;
            const sig = signClaim(w, distributorAddress);
            const resp = await distributor.claim(sig);
            Assert.expect(resp.error).toBeUndefined();
        }

        // Verify balances
        for (const w of wallets) {
            const pillBal = await pill.balanceOf(w.address);
            const motoBal = await moto.balanceOf(w.address);
            Assert.expect(pillBal).toEqual(PILL_AMOUNT);
            Assert.expect(motoBal).toEqual(MOTO_AMOUNT);
        }
        vm.success('3 users claimed');
    });
});
