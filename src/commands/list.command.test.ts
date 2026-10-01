import {assert, assertWrap} from '@augment-vir/assert';
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

async function withCertificatesDir<T>(
    fileNames: Readonly<{
        leaf: ReadonlyArray<string>;
        root: ReadonlyArray<string>;
    }>,
    callback: (certificatesDirPath: string) => Promise<T>,
) {
    await mkdir(notCommittedDirPath, {
        recursive: true,
    });
    const certificatesDirPath = await mkdtemp(join(notCommittedDirPath, 'cert-vir-list-test-'));
    const rootDirPath = join(certificatesDirPath, 'root');

    await mkdir(rootDirPath, {
        recursive: true,
    });
    await Promise.all([
        ...fileNames.leaf.map(async (fileName) => {
            await writeFile(join(certificatesDirPath, fileName), '');
        }),
        ...fileNames.root.map(async (fileName) => {
            await writeFile(join(rootDirPath, fileName), '');
        }),
    ]);

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
    it('lists only certificates, ignoring keys and the root directory', async () => {
        await withCertificatesDir(
            {
                leaf: [
                    'my-site.crt',
                    'my-site.key',
                    'my-site.csr',
                    'another-site.crt',
                ],
                root: [
                    'rootCA.crt',
                    'rootCA.key',
                ],
            },
            async (certificatesDirPath) => {
                assert.deepEquals(
                    await listCertificates({
                        certificatesDirPath,
                    }),
                    {
                        certificatesDirPath,
                        leafCertificateNames: [
                            'another-site',
                            'my-site',
                        ],
                        rootCertificateNames: ['rootCA'],
                        rootCertificatesDirPath: join(certificatesDirPath, 'root'),
                    },
                );
            },
        );
    });

    it('reads the given root certificates directory name', async () => {
        await withCertificatesDir(
            {
                leaf: [],
                root: ['rootCA.crt'],
            },
            async (certificatesDirPath) => {
                assert.deepEquals(
                    await listCertificates({
                        certificatesDirPath,
                        rootCertificatesDirName: 'authority',
                    }),
                    {
                        certificatesDirPath,
                        leafCertificateNames: [],
                        rootCertificateNames: [],
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
    it('logs every certificate name', async () => {
        await withCertificatesDir(
            {
                leaf: ['my-site.crt'],
                root: ['rootCA.crt'],
            },
            async (certificatesDirPath) => {
                const output = await captureStandardOutput(async () => {
                    await runListCertificatesCommand({
                        certificatesDirPath,
                    });
                });

                assert.isIn('rootCA', output);
                assert.isIn('my-site', output);
            },
        );
    });

    it('logs that an empty directory has no certificates', async () => {
        await withCertificatesDir(
            {
                leaf: [],
                root: [],
            },
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
