import {check, checkWrap} from '@augment-vir/assert';
import {type MaybePromise} from '@augment-vir/common';
import {input, password} from '@inquirer/prompts';
import {FlagRequirement, parseArgs, type ArgDefinitions, type ParseArgsParams} from 'cli-vir';
import {runCertVir, type CommandParams} from './api.js';
import {CertVirCommand} from './command.js';

/**
 * Run the raw interactive cert-vir CLI.
 *
 * @category CLI
 */
export async function runCertVirCli(
    command: CertVirCommand,
    args: ReadonlyArray<string>,
): Promise<void> {
    const params = await extractParams[command](args);

    await runCertVir({
        [command]: params,
    } as any);
}

/**
 * The bin name here is only used to label the generated help message. It includes a space so that
 * it can never match an already-stripped arg and truncate the args that follow it.
 */
function createParseArgsParams(command: CertVirCommand) {
    return {
        binName: `cert-vir ${command}`,
        importMeta: import.meta,
    } satisfies ParseArgsParams;
}

const commonArgDefinitions = {
    certificatesDirPath: {
        description: 'The directory wherein your certificates are saved.',
        flag: {
            valueRequirement: FlagRequirement.Required,
        },
    },
    rootCertificateName: {
        description: "The root certificate's file name, without its extension.",
        flag: {
            valueRequirement: FlagRequirement.Required,
        },
    },
    rootCertificatePath: {
        description:
            "A full path directly to the root certificate's '.crt' file. Overrides all other root certificate path flags.",
        flag: {
            valueRequirement: FlagRequirement.Required,
        },
    },
    rootCertificatesDirName: {
        description: 'The folder, within the certificates directory, that holds root certificates.',
        flag: {
            valueRequirement: FlagRequirement.Required,
        },
    },
} satisfies ArgDefinitions;

const passwordArgDefinition = {
    rootCertificationEncryptionPassword: {
        description: "The encryption password for your root certificate's key.",
        flag: {
            valueRequirement: FlagRequirement.Required,
        },
    },
} satisfies ArgDefinitions;

/**
 * Extract the parameters for each command from the input raw args. Optional parameters are only
 * accepted as flag inputs (`--<property-name> value`) while required inputs, if not provided in the
 * same flag way, are prompted from the user.
 *
 * @category Internal
 */
export const extractParams: Readonly<{
    [Command in CertVirCommand]: (
        ars: ReadonlyArray<string>,
    ) => MaybePromise<CommandParams[Command]>;
}> = {
    async [CertVirCommand.Root](args) {
        const parsed = parseArgs(
            args,
            {
                ...commonArgDefinitions,
                ...passwordArgDefinition,
                rootCertificateCommonName: {
                    description: 'The common name (CN) for your root certificate.',
                    flag: {
                        valueRequirement: FlagRequirement.Required,
                    },
                },
                rootCertificateOrganizationName: {
                    description: 'The organization name (O) for your root certificate.',
                    flag: {
                        valueRequirement: FlagRequirement.Required,
                    },
                },
            },
            createParseArgsParams(CertVirCommand.Root),
        );

        return {
            ...extractCommonParams(parsed),
            rootCertificateCommonName:
                checkWrap.isString(parsed.rootCertificateCommonName) ||
                (await input({
                    message: 'Root certificate common name:',
                })),
            rootCertificateOrganizationName:
                checkWrap.isString(parsed.rootCertificateOrganizationName) ||
                (await input({
                    message: 'Root certificate organization name:',
                })),
            rootCertificationEncryptionPassword: await extractPassword(parsed),
        };
    },
    async [CertVirCommand.Leaf](args) {
        const parsed = parseArgs(
            args,
            {
                ...commonArgDefinitions,
                ...passwordArgDefinition,
                certificateCommonName: {
                    description: 'The common name (CN) for the new leaf certificate.',
                    flag: {
                        valueRequirement: FlagRequirement.Required,
                    },
                },
                certificateFileName: {
                    description: "The new leaf certificate's file name, without its extension.",
                    flag: {
                        valueRequirement: FlagRequirement.Required,
                    },
                },
                domainNames: {
                    description:
                        'A domain name to include in the certificate. Set this flag multiple times for multiple domains.',
                    flag: {
                        allowMultiple: true,
                        valueRequirement: FlagRequirement.Required,
                    },
                },
                ipAddresses: {
                    description:
                        'An IP address to include in the certificate. Set this flag multiple times for multiple addresses.',
                    flag: {
                        allowMultiple: true,
                        valueRequirement: FlagRequirement.Required,
                    },
                },
            },
            createParseArgsParams(CertVirCommand.Leaf),
        );

        const domainNames = parsed.domainNames.filter(check.isString);
        const ipAddresses = parsed.ipAddresses.filter(check.isString);

        return {
            ...extractCommonParams(parsed),
            certificateCommonName:
                checkWrap.isString(parsed.certificateCommonName) ||
                (await input({
                    message: 'Certificate common name:',
                })),
            certificateFileName:
                checkWrap.isString(parsed.certificateFileName) ||
                (await input({
                    message: 'Certificate file name, without its extension:',
                })),
            ...(domainNames.length || ipAddresses.length
                ? {
                      domainNames,
                      ipAddresses,
                  }
                : {
                      domainNames: await promptCommaSeparated('Domain names, comma separated:'),
                      ipAddresses: await promptCommaSeparated('IP addresses, comma separated:'),
                  }),
            rootCertificationEncryptionPassword: await extractPassword(parsed),
        };
    },
    [CertVirCommand.Trust](args) {
        return {
            ...extractCommonParams(
                parseArgs(args, commonArgDefinitions, createParseArgsParams(CertVirCommand.Trust)),
            ),
            /** The trust command never reads the root certificate's key, so it needs no password. */
            rootCertificationEncryptionPassword: '',
        };
    },
};

/**
 * `rootCertificatePath` is only included when it was actually provided because
 * `getRootCertificatePaths` picks its path strategy by checking for that key's presence, not its
 * value.
 */
function extractCommonParams(
    parsed: Readonly<{
        certificatesDirPath: string | boolean;
        rootCertificateName: string | boolean;
        rootCertificatePath: string | boolean;
        rootCertificatesDirName: string | boolean;
    }>,
) {
    return {
        certificatesDirPath: checkWrap.isString(parsed.certificatesDirPath),
        ...(check.isString(parsed.rootCertificatePath)
            ? {
                  rootCertificatePath: parsed.rootCertificatePath,
              }
            : {
                  rootCertificateName: checkWrap.isString(parsed.rootCertificateName),
                  rootCertificatesDirName: checkWrap.isString(parsed.rootCertificatesDirName),
              }),
    };
}

async function extractPassword(
    parsed: Readonly<{
        rootCertificationEncryptionPassword: string | boolean;
    }>,
) {
    return (
        checkWrap.isString(parsed.rootCertificationEncryptionPassword) ||
        (await password({
            mask: true,
            message: 'Root certificate encryption password:',
        }))
    );
}

async function promptCommaSeparated(message: string) {
    return (
        await input({
            message,
        })
    )
        .split(',')
        .map((entry) => entry.trim())
        .filter(check.isTruthy);
}
