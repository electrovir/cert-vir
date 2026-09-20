#!/usr/bin/env node

import {log} from '@augment-vir/common';
import {parseArgs} from 'cli-vir';
import {runCertVirCli} from './cli.js';
import {CertVirCommand} from './command.js';

const {command, args} = parseArgs(
    process.argv,
    {
        command: {
            position: {
                disableFlags: true,
                index: 0,
            },
            required: true,
            type: CertVirCommand,
        },
        args: {
            position: {
                rest: true,
            },
        },
    },
    {
        binName: 'cert-vir',
        importMeta: import.meta,
    },
);

try {
    await runCertVirCli(command, args);
    log.success(`cert-vir ${command} complete.`);
} catch (error) {
    log.error(error);
}
