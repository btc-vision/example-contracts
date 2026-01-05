/**
 * OPNet Package Registry - Entry Point
 *
 * Decentralized package registry for OPNet plugins.
 * Manages package ownership, version metadata, and deprecation status.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { Blockchain } from '@btc-vision/btc-runtime/runtime';
import { revertOnError } from '@btc-vision/btc-runtime/runtime/abort/abort';
import { PackageRegistry } from './PackageRegistry';

// DO NOT TOUCH THIS.
Blockchain.contract = (): PackageRegistry => {
    // ONLY CHANGE THE CONTRACT CLASS NAME.
    // DO NOT ADD CUSTOM LOGIC HERE.
    return new PackageRegistry();
};

// VERY IMPORTANT
export * from '@btc-vision/btc-runtime/runtime/exports';

// VERY IMPORTANT
export function abort(message: string, fileName: string, line: u32, column: u32): void {
    revertOnError(message, fileName, line, column);
}
