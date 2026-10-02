/* node:coverage disable file */

import {check, checkWrap} from '@augment-vir/assert';
import {log, type MaybePromise, shellQuote} from '@augment-vir/common';
import {
    currentOperatingSystem,
    OperatingSystem,
    readFileIfExists,
    runShellCommand,
} from '@augment-vir/node';
import {writeFile} from 'node:fs/promises';
import {homedir} from 'node:os';
import {basename, dirname, join} from 'node:path';
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
    const rootCrtFilePath = getRootCertificatePaths(params).rootCrtFilePath;

    await operatingSystemCommands[currentOperatingSystem]({
        rootCrtFilePath,
    });
    await setNodeExtraCaCertsInShellConfig({
        rootCrtFilePath,
    });
}

/**
 * Point `NODE_EXTRA_CA_CERTS` at the given root certificate in the current shell's config file. An
 * `export` of it that already points at some other file is left alone, because the variable holds a
 * single file path and overwriting it would stop Node from trusting that file's certificates.
 *
 * Node.js reads its own bundled certificate list instead of the operating system's trust store, so
 * trusting the root certificate with the operating system is not enough to make Node trust it.
 *
 * @category Internal
 */
export async function setNodeExtraCaCertsInShellConfig({
    rootCrtFilePath,
}: Readonly<{
    rootCrtFilePath: string;
}>) {
    const exportLinePrefix = `export ${nodeExtraCaCertsVarName}=`;
    const exportLine = `${exportLinePrefix}${shellQuote(rootCrtFilePath)}`;
    const shellConfigFilePath = await getShellConfigFilePath();

    if (!shellConfigFilePath) {
        log.warning(
            [
                `Shell '${process.env.SHELL || ''}' is not supported, so ${nodeExtraCaCertsVarName} was not set.`,
                "Add this to your shell's config file yourself:",
                `    ${exportLine}`,
            ].join('\n'),
        );
        return;
    }

    const existingContents = (await readFileIfExists(shellConfigFilePath)) || '';
    /** The last export is the one the shell ends up using, so it is the only one worth reading. */
    const existingExportLine =
        existingContents
            .split('\n')
            .findLast((line) => line.trimStart().startsWith(exportLinePrefix)) || '';

    if (existingExportLine) {
        const existingFilePath = existingExportLine
            .trim()
            .slice(exportLinePrefix.length)
            .replace(/^(['"])(.*)\1$/, '$2');

        if (existingFilePath === rootCrtFilePath) {
            log.info(
                `${nodeExtraCaCertsVarName} in '${shellConfigFilePath}' already points at '${rootCrtFilePath}'.`,
            );
        } else {
            const combinedCrtFilePath = shellQuote(
                join(dirname(rootCrtFilePath), 'node-extra-ca-certs.crt'),
            );

            log.warning(
                [
                    `'${shellConfigFilePath}' already exports ${nodeExtraCaCertsVarName} as '${existingFilePath}', so it was left alone.`,
                    'Node reads a single file from that variable, so point it at a file holding both certificates instead:',
                    `    cat ${shellQuote(existingFilePath)} ${shellQuote(rootCrtFilePath)} > ${combinedCrtFilePath}`,
                    `    ${exportLinePrefix}${combinedCrtFilePath}`,
                ].join('\n'),
            );
        }

        return;
    }

    await writeFile(
        shellConfigFilePath,
        `${[
            existingContents.trimEnd(),
            exportLine,
        ]
            .filter(check.isTruthy)
            .join('\n')}\n`,
    );

    log.info(
        [
            `Set ${nodeExtraCaCertsVarName} in '${shellConfigFilePath}'.`,
            `To pick it up, open a new terminal or run: source ${shellQuote(shellConfigFilePath)}`,
        ].join('\n'),
    );
}

/**
 * The config file for the shell that this process was started from, or `undefined` if that shell
 * has no config file that this command knows how to edit.
 *
 * @category Internal
 */
export async function getShellConfigFilePath() {
    const shell = checkWrap.isEnumValue(basename(process.env.SHELL || ''), SupportedShell);

    return shell && join(await readUserHomeDirPath(), shellConfigFileNames[shell]);
}

const nodeExtraCaCertsVarName = 'NODE_EXTRA_CA_CERTS';

/** The shells whose config file this command knows how to edit. */
enum SupportedShell {
    Bash = 'bash',
    Zsh = 'zsh',
}

const shellConfigFileNames: Readonly<Record<SupportedShell, string>> = {
    [SupportedShell.Bash]: '.bashrc',
    [SupportedShell.Zsh]: '.zshrc',
};

/**
 * Trusting a root certificate needs `sudo`, and `sudo` may hand this process root's `HOME` instead
 * of the home directory that holds the shell config file worth editing. The user name is checked
 * against a pattern first because tilde expansion only happens on an unquoted word, so `shellQuote`
 * cannot be used on it.
 */
async function readUserHomeDirPath() {
    const sudoUserName = process.env.SUDO_USER || '';

    if (!/^[\w.-]+$/.test(sudoUserName)) {
        return homedir();
    }

    const {stdout} = await runShellCommand(`echo ~${sudoUserName}`);

    return stdout.trim() || homedir();
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
