/* eslint-disable sonarjs/no-hardcoded-passwords */
// cspell:words passin passout

import {assert} from '@augment-vir/assert';
import {replaceExtension} from '@augment-vir/common';
import {runShellCommand} from '@augment-vir/node';
import {describe, it} from '@augment-vir/test';
import {mkdir, mkdtemp, readFile, rm, stat} from 'node:fs/promises';
import {join} from 'node:path';
import {notCommittedDirPath} from '../file-paths.mock.js';
import {defaultCertificatesDirPath, passwordEnvVarName} from './common.js';
import {
    createCertificateConfigFile,
    runLeafCertificateCommand,
    type LeafCommandParams,
} from './leaf.command.js';

const rootCertificationEncryptionPassword = 'test-password';

/**
 * Builds a root certificate without going through `runRootCertificateCommand` so that a failure
 * there cannot mask a leaf failure here. `< /dev/null` is required because openssl ignores
 * `-passin` when its stdin is a pipe.
 */
async function createRootCertificateFixture(certificatesDirPath: string) {
    const rootDirPath = join(certificatesDirPath, 'root');
    await mkdir(rootDirPath, {
        recursive: true,
    });

    const rootKeyFilePath = join(rootDirPath, 'rootCA.key');
    const rootCrtFilePath = join(rootDirPath, 'rootCA.crt');
    const env = {
        ...process.env,
        [passwordEnvVarName]: rootCertificationEncryptionPassword,
    };

    await runShellCommand(
        `openssl genrsa -aes256 -passout env:${passwordEnvVarName} -out '${rootKeyFilePath}' 2048 < /dev/null`,
        {
            env,
            rejectOnError: true,
        },
    );
    await runShellCommand(
        `openssl req -x509 -new -key '${rootKeyFilePath}' -sha256 -days 3650 -out '${rootCrtFilePath}' -passin env:${passwordEnvVarName} -subj "/CN=Test Root" < /dev/null`,
        {
            env,
            rejectOnError: true,
        },
    );
}

describe(createCertificateConfigFile.name, () => {
    it('includes every alt name entry', () => {
        const configFileContents = createCertificateConfigFile({
            certificateCommonName: 'localhost',
            certificateFileName: 'my-site.crt',
            domainNames: [
                'localhost',
                'dev.localhost',
            ],
            ipAddresses: ['127.0.0.1'],
        });

        assert.isIn('CN = localhost', configFileContents);
        assert.isIn('DNS.0 = localhost', configFileContents);
        assert.isIn('DNS.1 = dev.localhost', configFileContents);
        assert.isIn('IP.0 = 127.0.0.1', configFileContents);
    });

    it('accepts ip addresses alone', () => {
        assert.isIn(
            'IP.0 = 127.0.0.1',
            createCertificateConfigFile({
                certificateCommonName: 'localhost',
                certificateFileName: 'my-site.crt',
                ipAddresses: ['127.0.0.1'],
            }),
        );
    });

    it('rejects a certificate with no alt names', () => {
        assert.throws(
            () => {
                createCertificateConfigFile({
                    certificateCommonName: 'localhost',
                    certificateFileName: 'my-site.crt',
                });
            },
            {
                matchMessage: 'No DNS or IP entries provided',
            },
        );
    });
});

describe(runLeafCertificateCommand.name, () => {
    it('signs a leaf certificate with the root certificate', async () => {
        await mkdir(notCommittedDirPath, {
            recursive: true,
        });
        const certificatesDirPath = await mkdtemp(join(notCommittedDirPath, 'cert-vir-leaf-test-'));

        try {
            await createRootCertificateFixture(certificatesDirPath);

            await runLeafCertificateCommand({
                certificateCommonName: 'localhost',
                certificateFileName: 'my-site.crt',
                certificatesDirPath,
                domainNames: ['localhost'],
                rootCertificationEncryptionPassword,
            });

            assert.isAbove((await stat(join(certificatesDirPath, 'my-site.crt'))).size, 0);
            assert.isAbove((await stat(join(certificatesDirPath, 'my-site.key'))).size, 0);
        } finally {
            await rm(certificatesDirPath, {
                force: true,
                recursive: true,
            });
        }
    });

    it('renews an existing certificate without replacing its key', async () => {
        await mkdir(notCommittedDirPath, {
            recursive: true,
        });
        const certificatesDirPath = await mkdtemp(
            join(notCommittedDirPath, 'cert-vir-renew-test-'),
        );

        try {
            await createRootCertificateFixture(certificatesDirPath);

            const params: Readonly<LeafCommandParams> = {
                certificateCommonName: 'localhost',
                certificateFileName: 'my-site.crt',
                certificatesDirPath,
                domainNames: ['localhost'],
                rootCertificationEncryptionPassword,
            };

            await runLeafCertificateCommand(params);
            const originalKey = await readFile(join(certificatesDirPath, 'my-site.key'), 'utf8');
            const originalCertificate = await readFile(
                join(certificatesDirPath, 'my-site.crt'),
                'utf8',
            );

            await runLeafCertificateCommand(params);

            assert.strictEquals(
                await readFile(join(certificatesDirPath, 'my-site.key'), 'utf8'),
                originalKey,
            );
            /** A renewed certificate carries a new serial number, so its contents must differ. */
            assert.notStrictEquals(
                await readFile(join(certificatesDirPath, 'my-site.crt'), 'utf8'),
                originalCertificate,
            );
        } finally {
            await rm(certificatesDirPath, {
                force: true,
                recursive: true,
            });
        }
    });

    it('writes into the default certificates directory when none is given', async () => {
        const certificateFileName = 'cert-vir-default-path-test.crt';
        const expectedKeyFilePath = join(
            defaultCertificatesDirPath,
            'cert-vir-default-path-test.key',
        );

        try {
            /**
             * Signing needs a root certificate that this test deliberately does not create; the
             * signing step is covered by the test above. Only the resolved output path matters
             * here.
             */
            await runLeafCertificateCommand({
                certificateCommonName: 'localhost',
                certificateFileName,
                domainNames: ['localhost'],
                rootCertificationEncryptionPassword,
            }).catch(() => undefined);

            assert.isAbove((await stat(expectedKeyFilePath)).size, 0);
        } finally {
            await Promise.all(
                [
                    '.key',
                    '.csr',
                    '.crt',
                ].map(async (newExtension) => {
                    const filePath = replaceExtension({
                        newExtension,
                        path: expectedKeyFilePath,
                    });

                    await rm(filePath, {
                        force: true,
                    });
                }),
            );
        }
    });
});
