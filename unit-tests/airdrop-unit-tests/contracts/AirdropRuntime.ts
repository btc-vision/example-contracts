import { Address, BinaryReader, BinaryWriter } from '@btc-vision/transaction';
import { BytecodeManager, CallResponse, ContractRuntime } from '@btc-vision/unit-test-framework';

export class AirdropRuntime extends ContractRuntime {
    // Selectors derived from ABI signatures
    private readonly claimSelector: number = this.getSelector('claim(bytes)');
    private readonly pauseSelector: number = this.getSelector('pause()');
    private readonly unpauseSelector: number = this.getSelector('unpause()');
    private readonly mintInfoSelector: number = this.getSelector('mintInfo()');

    // Standard OP20 selectors
    private readonly balanceOfSelector: number = this.getSelector('balanceOf(address)');
    private readonly totalSupplySelector: number = this.getSelector('totalSupply()');

    public constructor(
        deployer: Address,
        address: Address,
        deploymentCalldata?: Buffer,
        gasLimit: bigint = 300_000_000_000n,
    ) {
        super({
            address,
            deployer,
            gasLimit,
            deploymentCalldata,
        });
    }

    public async claim(
        signature: Uint8Array,
        sender?: Address,
        txOrigin?: Address,
    ): Promise<CallResponse> {
        const calldata = new BinaryWriter();
        calldata.writeSelector(this.claimSelector);
        calldata.writeBytesWithLength(signature);

        const response = await this.execute({
            calldata: calldata.getBuffer(),
            ...(sender ? { sender } : {}),
            ...(txOrigin ? { txOrigin } : {}),
        });

        return response;
    }

    public async pause(sender?: Address): Promise<CallResponse> {
        const calldata = new BinaryWriter();
        calldata.writeSelector(this.pauseSelector);

        const response = await this.execute({
            calldata: calldata.getBuffer(),
            ...(sender ? { sender, txOrigin: sender } : {}),
        });

        return response;
    }

    public async unpause(sender?: Address): Promise<CallResponse> {
        const calldata = new BinaryWriter();
        calldata.writeSelector(this.unpauseSelector);

        const response = await this.execute({
            calldata: calldata.getBuffer(),
            ...(sender ? { sender, txOrigin: sender } : {}),
        });

        return response;
    }

    public async mintInfo(): Promise<{
        startBlock: bigint;
        endBlock: bigint;
        paused: boolean;
        mintAmount: bigint;
    }> {
        const calldata = new BinaryWriter();
        calldata.writeSelector(this.mintInfoSelector);

        const response = await this.execute({ calldata: calldata.getBuffer() });
        this.handleResponse(response);

        const reader = new BinaryReader(response.response);
        return {
            startBlock: reader.readU64(),
            endBlock: reader.readU64(),
            paused: reader.readBoolean(),
            mintAmount: reader.readU256(),
        };
    }

    public async balanceOf(owner: Address): Promise<bigint> {
        const calldata = new BinaryWriter();
        calldata.writeSelector(this.balanceOfSelector);
        calldata.writeAddress(owner);

        const response = await this.execute({ calldata: calldata.getBuffer() });
        this.handleResponse(response);

        const reader = new BinaryReader(response.response);
        return reader.readU256();
    }

    public async totalSupply(): Promise<bigint> {
        const calldata = new BinaryWriter();
        calldata.writeSelector(this.totalSupplySelector);

        const response = await this.execute({ calldata: calldata.getBuffer() });
        this.handleResponse(response);

        const reader = new BinaryReader(response.response);
        return reader.readU256();
    }

    protected handleError(error: Error): Error {
        return new Error(`(AirdropToken: ${this.address}) OP_NET: ${error.message}`);
    }

    protected defineRequiredBytecodes(): void {
        BytecodeManager.loadBytecode('./bytecodes/AirdropToken.wasm', this.address);
    }

    private getSelector(signature: string): number {
        return Number(`0x${this.abiCoder.encodeSelector(signature)}`);
    }

    private handleResponse(response: CallResponse): void {
        if (response.error) throw this.handleError(response.error);
        if (!response.response) throw new Error('No response to decode');
    }
}
