import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Blockchain,
    Calldata,
    OP20,
    OP20InitParameters,
} from '@btc-vision/btc-runtime/runtime';

@final
export class WBTC extends OP20 {
    public constructor() {
        super();
    }

    public override onDeployment(_calldata: Calldata): void {
        const maxSupply: u256 = u256.fromU64(2_100_000_000_000_000);
        const decimals: u8 = 8;
        const name: string = 'Wrapped Bitcoin';
        const symbol: string = 'WBTC';

        this.instantiate(new OP20InitParameters(maxSupply, decimals, name, symbol));

        this._mint(Blockchain.tx.origin, maxSupply);
    }

    public override onUpdate(_calldata: Calldata): void {
        super.onUpdate(_calldata);
    }
}
