import {
    Address,
    ADDRESS_BYTE_LENGTH,
    BytesWriter,
    NetEvent,
    U256_BYTE_LENGTH,
    U64_BYTE_LENGTH,
} from '@btc-vision/btc-runtime/runtime';

@final
export class MintCounterEvent extends NetEvent {
    constructor(user: Address, userMints: u64, total: u64) {
        const eventData: BytesWriter = new BytesWriter(
            ADDRESS_BYTE_LENGTH + U256_BYTE_LENGTH + U64_BYTE_LENGTH * 2,
        );

        eventData.writeAddress(user);
        eventData.writeU64(userMints);
        eventData.writeU64(total);

        super('MintCounter', eventData);
    }
}
