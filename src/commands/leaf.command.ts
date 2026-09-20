// cspell:words extfile cacreateserial passin tcgetattr

import {
    replaceExtension,
    shellQuote,
    wrapInTry,
    type PartialWithUndefined,
} from '@augment-vir/common';
import {runShellCommand, writeFileAndDir} from '@augment-vir/node';
import {chmod, mkdir, stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {
    defaultCertificatesDirPath,
    getRootCertificatePaths,
    passwordEnvVarName,
    type CommonCertificateCommandParams,
} from './common.js';

/**
 * Params for {@link createCertificateConfigFile}.
 *
 * @category Internal
 */
export type LeafCertificateConfigParams = {
    certificateCommonName: string;
    certificateFileName: string;
} & PartialWithUndefined<{
    domainNames: string[];
    ipAddresses: string[];
}>;

/**
 * Params for {@link runLeafCertificateCommand}.
 *
 * @category Internal
 */
export type LeafCommandParams = LeafCertificateConfigParams & CommonCertificateCommandParams;

/**
 * Run the leaf command.
 *
 * @category Internal
 */
export async function runLeafCertificateCommand(this: void, params: Readonly<LeafCommandParams>) {
    const {rootCrtFilePath, rootKeyFilePath} = getRootCertificatePaths(params);
    const configFileContents = createCertificateConfigFile(params);
    const configFilePath = join(
        tmpdir(),
        'cert-vir',
        replaceExtension({
            path: params.certificateFileName,
            newExtension: '.cnf',
        }),
    );
    await writeFileAndDir(configFilePath, configFileContents);

    const leafCrtFilePath = join(
        params.certificatesDirPath || defaultCertificatesDirPath,
        replaceExtension({
            newExtension: '.crt',
            path: params.certificateFileName,
        }),
    );
    const leafKeyFilePath = replaceExtension({
        newExtension: '.key',
        path: leafCrtFilePath,
    });
    const leafCsrFilePath = replaceExtension({
        newExtension: '.csr',
        path: leafCrtFilePath,
    });

    await mkdir(dirname(leafCrtFilePath), {
        recursive: true,
    });

    const hasExistingKey = await wrapInTry(
        async () => {
            await stat(leafKeyFilePath);
            return true;
        },
        {
            fallbackValue: false,
        },
    );

    if (!hasExistingKey) {
        await runShellCommand(`openssl genrsa -out ${shellQuote(leafKeyFilePath)} 2048`, {
            rejectOnError: true,
        });
        await chmod(leafKeyFilePath, '400');
    }

    await runShellCommand(
        `openssl req -new -key ${shellQuote(leafKeyFilePath)} -out ${shellQuote(leafCsrFilePath)} -config ${shellQuote(configFilePath)}`,
        {
            rejectOnError: true,
        },
    );
    /**
     * `openssl` opens a console session whenever it loads an encrypted key, even though `-passin`
     * means it will never read from it. Without a controlling terminal it falls back to stdin, and
     * `tcgetattr` on the socket that `runShellCommand` puts there fails with an errno that
     * `openssl` treats as fatal. Redirecting stdin to `/dev/null` gives it a fd it accepts.
     */
    await runShellCommand(
        `openssl x509 -req -in ${shellQuote(leafCsrFilePath)} -passin env:${passwordEnvVarName} -CA ${shellQuote(rootCrtFilePath)} -CAkey ${shellQuote(rootKeyFilePath)} -CAcreateserial -out ${shellQuote(leafCrtFilePath)} -days 397 -sha256 -extfile ${shellQuote(configFilePath)} -extensions ext < /dev/null`,
        {
            env: {
                ...process.env,
                [passwordEnvVarName]: params.rootCertificationEncryptionPassword,
            },
            rejectOnError: true,
        },
    );
}

/**
 * Creates the config file contents for creating leaf certificate.
 *
 * @category Internal
 */
export function createCertificateConfigFile({
    certificateCommonName,
    domainNames,
    ipAddresses,
}: Readonly<LeafCertificateConfigParams>): string {
    const dnsEntries = createAltEntries({
        entryType: AltEntryType.DNS,
        values: domainNames,
    });
    const ipEntries = createAltEntries({
        entryType: AltEntryType.IP,
        values: ipAddresses,
    });

    if (!ipEntries && !dnsEntries) {
        throw new Error(
            'No DNS or IP entries provided for certificate. At least one must be provided.',
        );
    }

    return `
        [req]
        distinguished_name = dn
        req_extensions = ext
        prompt = no

        [dn]
        CN = ${certificateCommonName}

        [ext]
        basicConstraints = critical,CA:FALSE
        keyUsage = critical,digitalSignature,keyEncipherment
        extendedKeyUsage = serverAuth
        subjectAltName = @alt

        [alt]
        ${dnsEntries}
        ${ipEntries}
    `;
}

enum AltEntryType {
    DNS = 'DNS',
    IP = 'IP',
}

function createAltEntries({
    entryType,
    values,
}: Readonly<{
    entryType: AltEntryType;
    values: ReadonlyArray<string> | undefined;
}>) {
    return (values || [])
        .map((value, index) => {
            return `${entryType}.${index} = ${value}`;
        })
        .join('\n');
}
