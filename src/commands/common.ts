import {replaceExtension, type PartialWithUndefined} from '@augment-vir/common';
import {homedir} from 'node:os';
import {join} from 'node:path';

/**
 * Params that are shared between multiple certificate commands.
 *
 * @category Internal
 */
export type CommonCertificateCommandParams = (
    | PartialWithUndefined<{
          /**
           * The folder within certificatesDir wherein the root certificates will be saved.
           *
           * @default 'root'
           */
          rootCertificatesDirName: string;
          /**
           * The root certificate from which you will sign all child and leaf certificates.
           *
           * @default 'rootCA'
           */
          rootCertificateName: string;
      }>
    | {
          /**
           * A full path directly to the root certificate `'.crt'` file.
           *
           * @default undefined
           */
          rootCertificatePath: string;
      }
) & {
    /** The encryption password for your root certificate. */
    rootCertificationEncryptionPassword: string;
} & PartialWithUndefined<{
        /**
         * The directory wherein you save your certificates.
         *
         * @default '~/.config/cert-vir/'
         */
        certificatesDirPath: string;
    }>;

/**
 * The default value for `CommonCommandParams.certificatesDirPath`.
 *
 * @category Internal
 */
export const defaultCertificatesDirPath = join(homedir(), '.config', 'cert-vir');

/**
 * The default value for `CommonCommandParams.rootCertificatesDirName`
 *
 * @category Internal
 */
export const defaultRootCertificatesDirName = 'root';

/**
 * The default value for `CommonCommandParams.rootCertificateName`.
 *
 * @category Internal
 */
export const defaultRootCertificateName = 'rootCA';

/**
 * Construct a path to the root certificate.
 *
 * @category Internal
 */
export function getRootCertificatePaths(params: Readonly<CommonCertificateCommandParams>): {
    rootCrtFilePath: string;
    rootKeyFilePath: string;
} {
    if ('rootCertificatePath' in params) {
        return {
            rootCrtFilePath: replaceExtension({
                newExtension: '.crt',
                path: params.rootCertificatePath,
            }),
            rootKeyFilePath: replaceExtension({
                newExtension: '.key',
                path: params.rootCertificatePath,
            }),
        };
    } else {
        const rootCrtFilePath = join(
            params.certificatesDirPath || defaultCertificatesDirPath,
            params.rootCertificatesDirName || defaultRootCertificatesDirName,
            replaceExtension({
                path: params.rootCertificateName || defaultRootCertificateName,
                newExtension: '.crt',
            }),
        );

        return {
            rootCrtFilePath,
            rootKeyFilePath: replaceExtension({
                newExtension: '.key',
                path: rootCrtFilePath,
            }),
        };
    }
}

/**
 * The env var that the root certificate password is attached to.
 *
 * @category Internal
 */
export const passwordEnvVarName = 'CA_PASS';
