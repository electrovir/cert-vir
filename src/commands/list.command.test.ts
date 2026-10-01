// cspell:words cacreateserial extfile

import {assert, assertWrap} from '@augment-vir/assert';
import {runShellCommand} from '@augment-vir/node';
import {describe, it} from '@augment-vir/test';
import {mkdir, mkdtemp, rm, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {PassThrough} from 'node:stream';
import {notCommittedDirPath} from '../file-paths.mock.js';
import {defaultCertificatesDirPath} from './common.js';
import {listCertificates, runListCertificatesCommand} from './list.command.js';

/** `log` writes straight to `process.stdout`, so the whole stream has to be swapped out to read it. */
async function captureStandardOutput(callback: () => Promise<void>) {
    const originalStdout = assertWrap.isDefined(Object.getOwnPropertyDescriptor(process, 'stdout'));
    const capturedOutput = new PassThrough();

    Object.defineProperty(process, 'stdout', {
        configurable: true,
        value: capturedOutput,
    });

    try {
        await callback();
    } finally {
        Object.defineProperty(process, 'stdout', originalStdout);
    }

    return String(capturedOutput.read() || '');
}

async function createEmptyCertificatesDir() {
    await mkdir(notCommittedDirPath, {
        recursive: true,
    });
    const certificatesDirPath = await mkdtemp(join(notCommittedDirPath, 'cert-vir-list-test-'));

    await mkdir(join(certificatesDirPath, 'root'), {
        recursive: true,
    });

    return certificatesDirPath;
}

/**
 * Builds a root certificate plus one leaf signed by it, alongside the extra files that the list
 * command must ignore: a key, a CSR, and a `'.crt'` that openssl cannot parse.
 */
async function createPopulatedCertificatesDir() {
    const certificatesDirPath = await createEmptyCertificatesDir();
    const rootKeyFilePath = join(certificatesDirPath, 'root', 'rootCA.key');
    const rootCrtFilePath = join(certificatesDirPath, 'root', 'rootCA.crt');
    const leafKeyFilePath = join(certificatesDirPath, 'my-site.key');
    const leafCsrFilePath = join(certificatesDirPath, 'my-site.csr');
    const leafCrtFilePath = join(certificatesDirPath, 'my-site.crt');
    const configFilePath = join(certificatesDirPath, 'my-site.cnf');

    await writeFile(
        configFilePath,
        [
            '[req]',
            'distinguished_name=dn',
            'req_extensions=ext',
            'prompt=no',
            '[dn]',
            'CN=my-site.example.com',
            '[ext]',
            'subjectAltName=@alt',
            '[alt]',
            'DNS.0=my-site.example.com',
            'DNS.1=other.example.com',
            'IP.0=127.0.0.1',
        ].join('\n'),
    );
    await writeFile(join(certificatesDirPath, 'not-a-certificate.crt'), 'definitely not a key');

    await runShellCommand(`openssl genrsa -out ${rootKeyFilePath} 2048`, {
        rejectOnError: true,
    });
    await runShellCommand(
        `openssl req -x509 -new -key ${rootKeyFilePath} -sha256 -days 10 -out ${rootCrtFilePath} -subj "/CN=cert-vir List Test Root/O=cert-vir"`,
        {
            rejectOnError: true,
        },
    );
    await runShellCommand(`openssl genrsa -out ${leafKeyFilePath} 2048`, {
        rejectOnError: true,
    });
    await runShellCommand(
        `openssl req -new -key ${leafKeyFilePath} -out ${leafCsrFilePath} -config ${configFilePath}`,
        {
            rejectOnError: true,
        },
    );
    await runShellCommand(
        `openssl x509 -req -in ${leafCsrFilePath} -CA ${rootCrtFilePath} -CAkey ${rootKeyFilePath} -CAcreateserial -out ${leafCrtFilePath} -days 10 -sha256 -extfile ${configFilePath} -extensions ext`,
        {
            rejectOnError: true,
        },
    );

    return certificatesDirPath;
}

async function withCertificatesDir<T>(
    certificatesDirPath: string,
    callback: (certificatesDirPath: string) => Promise<T>,
) {
    try {
        return await callback(certificatesDirPath);
    } finally {
        await rm(certificatesDirPath, {
            force: true,
            recursive: true,
        });
    }
}

describe(listCertificates.name, () => {
    it('reads the common name, alt names, and issuer out of each certificate', async () => {
        await withCertificatesDir(
            await createPopulatedCertificatesDir(),
            async (certificatesDirPath) => {
                assert.deepEquals(
                    await listCertificates({
                        certificatesDirPath,
                    }),
                    {
                        certificatesDirPath,
                        leafCertificates: [
                            {
                                certificateFileName: 'my-site',
                                commonName: 'my-site.example.com',
                                domainNames: [
                                    'my-site.example.com',
                                    'other.example.com',
                                ],
                                ipAddresses: ['127.0.0.1'],
                                issuerCommonName: 'cert-vir List Test Root',
                            },
                            {
                                certificateFileName: 'not-a-certificate',
                                commonName: '',
                                domainNames: [],
                                ipAddresses: [],
                                issuerCommonName: '',
                            },
                        ],
                        rootCertificates: [
                            {
                                certificateFileName: 'rootCA',
                                commonName: 'cert-vir List Test Root',
                                domainNames: [],
                                ipAddresses: [],
                                issuerCommonName: 'cert-vir List Test Root',
                            },
                        ],
                        rootCertificatesDirPath: join(certificatesDirPath, 'root'),
                    },
                );
            },
        );
    });

    it('reads the given root certificates directory name', async () => {
        await withCertificatesDir(
            await createEmptyCertificatesDir(),
            async (certificatesDirPath) => {
                assert.deepEquals(
                    await listCertificates({
                        certificatesDirPath,
                        rootCertificatesDirName: 'authority',
                    }),
                    {
                        certificatesDirPath,
                        leafCertificates: [],
                        rootCertificates: [],
                        rootCertificatesDirPath: join(certificatesDirPath, 'authority'),
                    },
                );
            },
        );
    });

    it('falls back to the default certificates directory', async () => {
        assert.strictEquals(
            (await listCertificates({})).certificatesDirPath,
            defaultCertificatesDirPath,
        );
    });
});

describe(runListCertificatesCommand.name, () => {
    it('logs every certificate detail', async () => {
        await withCertificatesDir(
            await createPopulatedCertificatesDir(),
            async (certificatesDirPath) => {
                const output = await captureStandardOutput(async () => {
                    await runListCertificatesCommand({
                        certificatesDirPath,
                    });
                });

                assert.isIn('rootCA', output);
                assert.isIn('common name: cert-vir List Test Root', output);
                assert.isIn('my-site', output);
                assert.isIn('signed by: cert-vir List Test Root', output);
                assert.isIn('domain names: my-site.example.com, other.example.com', output);
                assert.isIn('ip addresses: 127.0.0.1', output);
            },
        );
    });

    it('logs that an empty directory has no certificates', async () => {
        await withCertificatesDir(
            await createEmptyCertificatesDir(),
            async (certificatesDirPath) => {
                assert.isIn(
                    'No leaf certificates',
                    await captureStandardOutput(async () => {
                        await runListCertificatesCommand({
                            certificatesDirPath,
                        });
                    }),
                );
            },
        );
    });
});
