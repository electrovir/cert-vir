/* eslint-disable sonarjs/no-hardcoded-passwords */

import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {mkdir, mkdtemp, rm, stat} from 'node:fs/promises';
import {join} from 'node:path';
import {notCommittedDirPath} from '../file-paths.mock.js';
import {runRootCertificateCommand} from './root.command.js';

describe(runRootCertificateCommand.name, () => {
    it('creates an encrypted key and a self-signed CA certificate', async () => {
        await mkdir(notCommittedDirPath, {
            recursive: true,
        });
        const certificatesDirPath = await mkdtemp(join(notCommittedDirPath, 'cert-vir-root-test-'));

        try {
            await runRootCertificateCommand({
                certificatesDirPath,
                rootCertificateCommonName: 'Test Root',
                rootCertificateOrganizationName: 'Test Org',
                rootCertificationEncryptionPassword: 'test-password',
            });

            const rootDirPath = join(certificatesDirPath, 'root');

            assert.isAbove((await stat(join(rootDirPath, 'rootCA.key'))).size, 0);
            assert.isAbove((await stat(join(rootDirPath, 'rootCA.crt'))).size, 0);
        } finally {
            await rm(certificatesDirPath, {
                force: true,
                recursive: true,
            });
        }
    });
});
