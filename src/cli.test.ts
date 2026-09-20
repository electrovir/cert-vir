/* eslint-disable sonarjs/no-hardcoded-passwords */
import {assert, assertWrap} from '@augment-vir/assert';
import {runShellCommand} from '@augment-vir/node';
import {describe, it} from '@augment-vir/test';
import {mkdir, mkdtemp, readFile, rm} from 'node:fs/promises';
import {join} from 'node:path';
import {PassThrough} from 'node:stream';
import {extractParams, runCertVirCli} from './cli.js';
import {CertVirCommand} from './command.js';
import {notCommittedDirPath} from './file-paths.mock.js';

/**
 * `@inquirer/prompts` reads `process.stdin` once per prompt and deliberately discards anything that
 * is already buffered when the prompt starts, so each prompt gets a fresh stream that only writes
 * its answer once the prompt has attached to it.
 */
async function withPromptAnswers<T>(answers: ReadonlyArray<string>, callback: () => Promise<T>) {
    const originalStdin = assertWrap.isDefined(Object.getOwnPropertyDescriptor(process, 'stdin'));
    const originalStdout = assertWrap.isDefined(Object.getOwnPropertyDescriptor(process, 'stdout'));
    const remainingAnswers = [...answers];
    const promptOutput = new PassThrough();
    promptOutput.resume();

    Object.defineProperty(process, 'stdin', {
        configurable: true,
        get() {
            const promptInput = new PassThrough();
            const answer = remainingAnswers.shift() || '';

            promptInput.once('resume', () => {
                setImmediate(() => {
                    setImmediate(() => {
                        promptInput.write(`${answer}\n`);
                    });
                });
            });

            return promptInput;
        },
    });
    Object.defineProperty(process, 'stdout', {
        configurable: true,
        value: promptOutput,
    });

    try {
        return await callback();
    } finally {
        Object.defineProperty(process, 'stdin', originalStdin);
        Object.defineProperty(process, 'stdout', originalStdout);
    }
}

describe('extractParams', () => {
    it('reads every root flag', async () => {
        assert.deepEquals(
            await extractParams[CertVirCommand.Root]([
                '--certificates-dir-path',
                '/certs',
                '--root-certificate-name',
                'my-root',
                '--root-certificates-dir-name',
                'authority',
                '--root-certificate-common-name',
                'My Root',
                '--root-certificate-organization-name',
                'My Org',
                '--root-certification-encryption-password',
                'flag-password',
            ]),
            {
                certificatesDirPath: '/certs',
                rootCertificateCommonName: 'My Root',
                rootCertificateName: 'my-root',
                rootCertificateOrganizationName: 'My Org',
                rootCertificatesDirName: 'authority',
                rootCertificationEncryptionPassword: 'flag-password',
            },
        );
    });

    it('prompts for every missing root value', async () => {
        assert.deepEquals(
            await withPromptAnswers(
                [
                    'Prompted Root',
                    'Prompted Org',
                    'prompted-password',
                ],
                async () => await extractParams[CertVirCommand.Root]([]),
            ),
            {
                certificatesDirPath: undefined,
                rootCertificateCommonName: 'Prompted Root',
                rootCertificateName: undefined,
                rootCertificateOrganizationName: 'Prompted Org',
                rootCertificatesDirName: undefined,
                rootCertificationEncryptionPassword: 'prompted-password',
            },
        );
    });

    it('prefers an explicit root certificate path over the root name flags', async () => {
        assert.deepEquals(
            await extractParams[CertVirCommand.Trust]([
                '--root-certificate-path',
                '/somewhere/else/my-root.crt',
            ]),
            {
                certificatesDirPath: undefined,
                rootCertificatePath: '/somewhere/else/my-root.crt',
                rootCertificationEncryptionPassword: '',
            },
        );
    });

    it('reads every leaf flag', async () => {
        assert.deepEquals(
            await extractParams[CertVirCommand.Leaf]([
                '--certificate-common-name',
                'leaf.example.com',
                '--certificate-file-name',
                'my-leaf',
                '--domain-names',
                'leaf.example.com',
                '--domain-names',
                'other.example.com',
                '--ip-addresses',
                '127.0.0.1',
                '--root-certification-encryption-password',
                'flag-password',
            ]),
            {
                certificateCommonName: 'leaf.example.com',
                certificateFileName: 'my-leaf',
                certificatesDirPath: undefined,
                domainNames: [
                    'leaf.example.com',
                    'other.example.com',
                ],
                ipAddresses: ['127.0.0.1'],
                rootCertificateName: undefined,
                rootCertificatesDirName: undefined,
                rootCertificationEncryptionPassword: 'flag-password',
            },
        );
    });

    it('accepts ip addresses without any domain names', async () => {
        assert.deepEquals(
            (
                await extractParams[CertVirCommand.Leaf]([
                    '--certificate-common-name',
                    'leaf.example.com',
                    '--certificate-file-name',
                    'my-leaf',
                    '--ip-addresses',
                    '127.0.0.1',
                    '--root-certification-encryption-password',
                    'flag-password',
                ])
            ).domainNames,
            [],
        );
    });

    it('prompts for every missing leaf value', async () => {
        assert.deepEquals(
            await withPromptAnswers(
                [
                    'prompted.example.com',
                    'prompted-leaf',
                    'prompted.example.com, , other.example.com',
                    '127.0.0.1, , 127.0.0.2',
                    'prompted-password',
                ],
                async () => await extractParams[CertVirCommand.Leaf]([]),
            ),
            {
                certificateCommonName: 'prompted.example.com',
                certificateFileName: 'prompted-leaf',
                certificatesDirPath: undefined,
                domainNames: [
                    'prompted.example.com',
                    'other.example.com',
                ],
                ipAddresses: [
                    '127.0.0.1',
                    '127.0.0.2',
                ],
                rootCertificateName: undefined,
                rootCertificatesDirName: undefined,
                rootCertificationEncryptionPassword: 'prompted-password',
            },
        );
    });

    it('never asks the trust command for a password', async () => {
        assert.deepEquals(await extractParams[CertVirCommand.Trust]([]), {
            certificatesDirPath: undefined,
            rootCertificateName: undefined,
            rootCertificatesDirName: undefined,
            rootCertificationEncryptionPassword: '',
        });
    });
});

describe(runCertVirCli.name, () => {
    it('signs a leaf certificate from parsed flags', async () => {
        const certificatesDirPath = await createUnencryptedRootCertificate();

        try {
            await runCertVirCli(CertVirCommand.Leaf, [
                '--certificates-dir-path',
                certificatesDirPath,
                '--certificate-common-name',
                'cli-test.example.com',
                '--certificate-file-name',
                'cert-vir-cli-test-leaf',
                '--domain-names',
                'cli-test.example.com',
                '--root-certification-encryption-password',
                'unused-by-an-unencrypted-key',
            ]);

            assert.isIn(
                'BEGIN CERTIFICATE',
                await readFile(join(certificatesDirPath, 'cert-vir-cli-test-leaf.crt'), 'utf8'),
            );
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
    const certificatesDirPath = await mkdtemp(join(notCommittedDirPath, 'cert-vir-cli-test-'));
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
        `openssl req -x509 -new -key '${rootKeyFilePath}' -sha256 -days 3650 -out '${rootCrtFilePath}' -subj "/CN=cert-vir CLI Test Root"`,
        {
            rejectOnError: true,
        },
    );

    return certificatesDirPath;
}
