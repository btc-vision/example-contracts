import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    AddressMap,
    Blockchain,
    BytesWriter,
    Calldata,
    OP20,
    OP20InitParameters,
    SafeMath,
} from '@btc-vision/btc-runtime/runtime';

@final
export class MyToken extends OP20 {
    public constructor() {
        super();

        // IMPORTANT. THIS WILL RUN EVERYTIME THE CONTRACT IS INTERACTED WITH. FOR SPECIFIC INITIALIZATION, USE "onDeployment" METHOD.
    }

    // "solidityLikeConstructor" This is a solidity-like constructor. This method will only run once when the contract is deployed.
    public override onDeployment(_calldata: Calldata): void {
        const maxSupply: u256 = u256.fromString('1000000000000000000000000000'); // Your max supply. (Here, 1 billion tokens)
        const decimals: u8 = 18; // Your decimals.
        const name: string = 'Test'; // Your token name.
        const symbol: string = 'TEST'; // Your token symbol.

        this.instantiate(new OP20InitParameters(maxSupply, decimals, name, symbol));

        // Add your logic here. Eg, minting the initial supply:
        // this._mint(Blockchain.tx.origin, maxSupply);
    }

    // "onUpdate" This method will run when the contract is UPDATED (REDEPLOYED).
    public override onUpdate(_calldata: Calldata): void {
        super.onUpdate(_calldata);

        // Add your logic here. If you want to REDEPLOY YOUR CONTRACT, this will be called as the "onDeployment of the new contract".
    }

    @method(
        {
            name: 'address',
            type: ABIDataTypes.ADDRESS,
        },
        {
            name: 'amount',
            type: ABIDataTypes.UINT256,
        },
    )
    @emit('Minted')
    @returns()
    public mint(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        this._mint(calldata.readAddress(), calldata.readU256());

        return new BytesWriter(0);
    }

    /**
     * Mints tokens to the specified addresses.
     *
     * @param calldata Calldata containing an `AddressMap<Address, u256>` to mint to.
     */
    @method({
        name: 'addressAndAmount',
        type: ABIDataTypes.ADDRESS_UINT256_TUPLE,
    })
    @emit('Minted')
    @returns()
    public airdrop(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const addressAndAmount: AddressMap<u256> = calldata.readAddressMapU256();
        const addresses: Address[] = addressAndAmount.keys();

        let totalAirdropped: u256 = u256.Zero;

        for (let i: i32 = 0; i < addresses.length; i++) {
            const address = addresses[i];
            if (!address) {
                throw new Error('Invalid address in airdrop list');
            }

            const amount = addressAndAmount.get(address);
            const currentBalance: u256 = this.balanceOfMap.get(address);

            if (currentBalance) {
                this.balanceOfMap.set(address, SafeMath.add(currentBalance, amount));
            } else {
                this.balanceOfMap.set(address, amount);
            }

            totalAirdropped = SafeMath.add(totalAirdropped, amount);

            this.createMintedEvent(address, amount);
        }

        this._totalSupply.set(SafeMath.add(this._totalSupply.value, totalAirdropped));

        return new BytesWriter(0);
    }
}
