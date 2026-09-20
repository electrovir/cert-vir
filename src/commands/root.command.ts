// cspell:words passout passin pathlen addext tcgetattr

import {shellQuote} from '@augment-vir/common';
import {runShellCommand} from '@augment-vir/node';
import {chmod, mkdir} from 'node:fs/promises';
import {dirname} from 'node:path';
import {
    getRootCertificatePaths,
    passwordEnvVarName,
    type CommonCertificateCommandParams,
} from './common.js';

/**
 * Params for {@link runRootCertificateCommand}.
 *
 * @category Internal
 */
export type RootCommandParams = {
    rootCertificateCommonName: string;
    rootCertificateOrganizationName: string;
} & CommonCertificateCommandParams;

/**
 * Run the root command.
 *
 * @category Internal
 */
export async function runRootCertificateCommand(this: void, params: Readonly<RootCommandParams>) {
    const {rootCrtFilePath, rootKeyFilePath} = getRootCertificatePaths(params);
    const rootCrtDirPath = dirname(rootCrtFilePath);

    await mkdir(dirname(rootCrtFilePath), {
        recursive: true,
    });
    await chmod(rootCrtDirPath, '700');

    await runShellCommand(
        `openssl genrsa -aes256 -passout env:${passwordEnvVarName} -out ${rootKeyFilePath} 4096`,
        {
            cwd: rootCrtDirPath,
            env: {
                ...process.env,
                [passwordEnvVarName]: params.rootCertificationEncryptionPassword,
            },
            rejectOnError: true,
        },
    );

    await chmod(rootKeyFilePath, '700');

    /**
     * `openssl` opens a console session whenever it loads an encrypted key, even though `-passin`
     * means it will never read from it. Without a controlling terminal it falls back to stdin, and
     * `tcgetattr` on the socket that `runShellCommand` puts there fails with an errno that
     * `openssl` treats as fatal. Redirecting stdin to `/dev/null` gives it a fd it accepts.
     */
    await runShellCommand(
        `openssl req -x509 -new -key ${shellQuote(rootKeyFilePath)} -sha256 -days 3650 -out ${shellQuote(rootCrtFilePath)} -passin env:${passwordEnvVarName} -subj "/CN=${params.rootCertificateCommonName}/O=${params.rootCertificateOrganizationName}" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" < /dev/null`,
        {
            env: {
                ...process.env,
                [passwordEnvVarName]: params.rootCertificationEncryptionPassword,
            },
            rejectOnError: true,
        },
    );
}
