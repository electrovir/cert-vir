import {getObjectTypedKeys, type MaybePromise, type RequireExactlyOne} from '@augment-vir/common';
import {CertVirCommand} from './command.js';
import {runLeafCertificateCommand, type LeafCommandParams} from './commands/leaf.command.js';
import {runRootCertificateCommand, type RootCommandParams} from './commands/root.command.js';
import {runTrustCertificateCommand, type TrustCommandParams} from './commands/trust.command.js';

/**
 * Params for {@link runCertVir}.
 *
 * @category Internal
 */
export type RunCertVirParams = RequireExactlyOne<{
    [Command in CertVirCommand]: CommandParams[Command];
}>;

/**
 * Run cert-vir.
 *
 * @category API
 */
export async function runCertVir(command: Readonly<RunCertVirParams>) {
    const commandToExecute = getObjectTypedKeys(command)[0];

    if (!commandToExecute) {
        throw new Error('No command provided.');
    }
    const commandParams = command[commandToExecute];

    if (!commandParams) {
        throw new Error('No command params provided.');
    }

    await commandOperators[commandToExecute](commandParams as any);
}

const commandOperators: Readonly<{
    [Command in CertVirCommand]: (
        this: void,
        params: Readonly<CommandParams[Command]>,
    ) => MaybePromise<void>;
}> = {
    [CertVirCommand.Leaf]: runLeafCertificateCommand,
    [CertVirCommand.Root]: runRootCertificateCommand,
    [CertVirCommand.Trust]: runTrustCertificateCommand,
};

/**
 * Params for each command, keyed by the command.
 *
 * @category Internal
 */
export type CommandParams = {
    [CertVirCommand.Leaf]: LeafCommandParams;
    [CertVirCommand.Root]: RootCommandParams;
    [CertVirCommand.Trust]: TrustCommandParams;
};
