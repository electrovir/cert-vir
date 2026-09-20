/* eslint-disable sonarjs/no-hardcoded-passwords */

import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {runCertVir, type RunCertVirParams} from './api.js';
import {CertVirCommand} from './command.js';

const rootCertificationEncryptionPassword = 'test-password';

describe(runCertVir.name, () => {
    it('dispatches to the command handler', async () => {
        /** Omitting all alt names makes the leaf handler reject before it shells out to openssl. */
        await assert.throws(
            runCertVir({
                [CertVirCommand.Leaf]: {
                    certificateCommonName: 'localhost',
                    certificateFileName: 'my-site.crt',
                    rootCertificationEncryptionPassword,
                },
            }),
            {
                matchMessage: 'No DNS or IP entries provided',
            },
        );
    });

    it('rejects when no command is given', async () => {
        await assert.throws(runCertVir({} as unknown as RunCertVirParams), {
            matchMessage: 'No command provided.',
        });
    });

    it('rejects when the command has no params', async () => {
        await assert.throws(
            runCertVir({
                [CertVirCommand.Root]: undefined,
            } as unknown as RunCertVirParams),
            {
                matchMessage: 'No command params provided.',
            },
        );
    });
});
