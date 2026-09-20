import {assert} from '@augment-vir/assert';
import {runShellCommand} from '@augment-vir/node';
import {describe, it} from '@augment-vir/test';
import {mkdir, mkdtemp, readFile, rm} from 'node:fs/promises';
import {join} from 'node:path';
import {notCommittedDirPath} from './file-paths.mock.js';

const scriptFilePath = join(import.meta.dirname, 'cli.script.ts');

describe('cli.script.ts', () => {
    it('signs a leaf certificate', async () => {
        const certificatesDirPath = await createUnencryptedRootCertificate();

        try {
            const {exitCode, stderr} = await runShellCommand(
                [
                    `npx tsx ${scriptFilePath} leaf`,
                    `--certificates-dir-path ${certificatesDirPath}`,
                    '--certificate-common-name script-test.example.com',
                    '--certificate-file-name cert-vir-script-test-leaf',
                    '--domain-names script-test.example.com',
                    '--root-certification-encryption-password unused-by-an-unencrypted-key',
                ].join(' '),
            );

            assert.strictEquals(exitCode, 0, stderr);
            assert.isIn(
                'BEGIN CERTIFICATE',
                await readFile(join(certificatesDirPath, 'cert-vir-script-test-leaf.crt'), 'utf8'),
            );
        } finally {
            await rm(certificatesDirPath, {
                force: true,
                recursive: true,
            });
        }
    });

    it('logs a failure without crashing', async () => {
        await mkdir(notCommittedDirPath, {
            recursive: true,
        });
        const certificatesDirPath = await mkdtemp(
            join(notCommittedDirPath, 'cert-vir-script-test-'),
        );

        try {
            const {exitCode, stderr} = await runShellCommand(
                [
                    `npx tsx ${scriptFilePath} leaf`,
                    `--certificates-dir-path ${certificatesDirPath}`,
                    '--root-certificate-path /this/root/does/not/exist.crt',
                    '--certificate-common-name script-test.example.com',
                    '--certificate-file-name cert-vir-script-failure-leaf',
                    '--domain-names script-test.example.com',
                    '--root-certification-encryption-password unused-by-a-missing-key',
                ].join(' '),
            );

            assert.strictEquals(exitCode, 0);
            assert.isIn('/this/root/does/not/exist.crt', stderr);
        } finally {
            await rm(certificatesDirPath, {
                force: true,
                recursive: true,
            });
        }
    });
});

/**
 * The key is intentionally left unencrypted: `openssl` only needs a passphrase for an encrypted
 * key, so this keeps the signing step from trying to read one from the terminal.
 */
async function createUnencryptedRootCertificate() {
    await mkdir(notCommittedDirPath, {
        recursive: true,
    });
    const certificatesDirPath = await mkdtemp(join(notCommittedDirPath, 'cert-vir-script-test-'));
    const rootDirPath = join(certificatesDirPath, 'root');
    const rootKeyFilePath = join(rootDirPath, 'rootCA.key');
    const rootCrtFilePath = join(rootDirPath, 'rootCA.crt');

    await mkdir(rootDirPath, {
        recursive: true,
    });
    await runShellCommand(`openssl genrsa -out '${rootKeyFilePath}' 2048`, {
        rejectOnError: true,
    });
    await runShellCommand(
        `openssl req -x509 -new -key '${rootKeyFilePath}' -sha256 -days 3650 -out '${rootCrtFilePath}' -subj "/CN=cert-vir Script Test Root"`,
        {
            rejectOnError: true,
        },
    );

    return certificatesDirPath;
}
