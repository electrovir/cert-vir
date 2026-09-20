/* eslint-disable sonarjs/no-hardcoded-passwords */

import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {homedir} from 'node:os';
import {join} from 'node:path';
import {getRootCertificatePaths} from './common.js';

const rootCertificationEncryptionPassword = 'test-password';

describe(getRootCertificatePaths.name, () => {
    it('prefers an explicit root certificate path', () => {
        assert.deepEquals(
            getRootCertificatePaths({
                rootCertificatePath: '/somewhere/else/my-root.crt',
                rootCertificationEncryptionPassword,
            }),
            {
                rootCrtFilePath: '/somewhere/else/my-root.crt',
                rootKeyFilePath: '/somewhere/else/my-root.key',
            },
        );
    });

    it('falls back to every default when nothing is provided', () => {
        const defaultRootDirPath = join(homedir(), '.config', 'cert-vir', 'root');

        assert.deepEquals(
            getRootCertificatePaths({
                rootCertificationEncryptionPassword,
            }),
            {
                rootCrtFilePath: join(defaultRootDirPath, 'rootCA.crt'),
                rootKeyFilePath: join(defaultRootDirPath, 'rootCA.key'),
            },
        );
    });

    it('uses provided directory and certificate names', () => {
        assert.deepEquals(
            getRootCertificatePaths({
                certificatesDirPath: '/certs',
                rootCertificateName: 'my-root',
                rootCertificatesDirName: 'authority',
                rootCertificationEncryptionPassword,
            }),
            {
                rootCrtFilePath: join('/certs', 'authority', 'my-root.crt'),
                rootKeyFilePath: join('/certs', 'authority', 'my-root.key'),
            },
        );
    });
});
