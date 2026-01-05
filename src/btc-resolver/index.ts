/**
 * OPNet BTC Name Resolver - Entry Point
 *
 * Decentralized domain name resolver for .btc domains.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { Blockchain } from '@btc-vision/btc-runtime/runtime';
import { revertOnError } from '@btc-vision/btc-runtime/runtime/abort/abort';
import { BtcNameResolver } from './BtcNameResolver';

// DO NOT TOUCH THIS.
Blockchain.contract = (): BtcNameResolver => {
    // ONLY CHANGE THE CONTRACT CLASS NAME.
    // DO NOT ADD CUSTOM LOGIC HERE.
    return new BtcNameResolver();
};

// VERY IMPORTANT
export * from '@btc-vision/btc-runtime/runtime/exports';

// VERY IMPORTANT
export function abort(message: string, fileName: string, line: u32, column: u32): void {
    revertOnError(message, fileName, line, column);
}
