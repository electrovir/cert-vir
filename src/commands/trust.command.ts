/* node:coverage disable file */

import {type MaybePromise, shellQuote} from '@augment-vir/common';
import {currentOperatingSystem, OperatingSystem, runShellCommand} from '@augment-vir/node';
import {type CommonCertificateCommandParams, getRootCertificatePaths} from './common.js';

/**
 * Params for the trust command.
 *
 * @category Internal
 */
export type TrustCommandParams = CommonCertificateCommandParams;

/**
 * Run the trust command.
 *
 * @category Internal
 */
export async function runTrustCertificateCommand(this: void, params: Readonly<TrustCommandParams>) {
    await operatingSystemCommands[currentOperatingSystem]({
        rootCrtFilePath: getRootCertificatePaths(params).rootCrtFilePath,
    });
}

const operatingSystemCommands: Readonly<
    Record<
        OperatingSystem,
        (
            params: Readonly<{
                rootCrtFilePath: string;
            }>,
        ) => MaybePromise<void>
    >
> = {
    async [OperatingSystem.Mac]({rootCrtFilePath}) {
        await runShellCommand(
            `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${shellQuote(rootCrtFilePath)}`,
            {
                rejectOnError: true,
            },
        );
    },
    [OperatingSystem.Linux]() {
        throw new Error('Trust command not implemented yet for Linux.');
    },
    [OperatingSystem.Windows]() {
        throw new Error('Trust command not implemented yet for Linux.');
    },
};
