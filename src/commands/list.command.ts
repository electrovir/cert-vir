import {extractExtension, log, wrapInTry, type PartialWithUndefined} from '@augment-vir/common';
import {readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {defaultCertificatesDirPath, defaultRootCertificatesDirName} from './common.js';

/**
 * Params for {@link runListCertificatesCommand}.
 *
 * @category Internal
 */
export type ListCommandParams = PartialWithUndefined<{
    /**
     * The directory wherein you save your certificates.
     *
     * @default '~/.config/cert-vir/'
     */
    certificatesDirPath: string;
    /**
     * The folder within certificatesDir wherein the root certificates are saved.
     *
     * @default 'root'
     */
    rootCertificatesDirName: string;
}>;

/**
 * Output of {@link listCertificates}.
 *
 * @category Internal
 */
export type CertificateList = {
    certificatesDirPath: string;
    /** Names of the leaf certificates, without their extensions, sorted alphabetically. */
    leafCertificateNames: string[];
    /** Names of the root certificates, without their extensions, sorted alphabetically. */
    rootCertificateNames: string[];
    rootCertificatesDirPath: string;
};

/**
 * Read the names of every certificate saved in the given certificates directory. Certificates are
 * identified by their `'.crt'` files, so a key without a certificate is not listed.
 *
 * @category Internal
 */
export async function listCertificates(
    params: Readonly<ListCommandParams>,
): Promise<CertificateList> {
    const certificatesDirPath = params.certificatesDirPath || defaultCertificatesDirPath;
    const rootCertificatesDirPath = join(
        certificatesDirPath,
        params.rootCertificatesDirName || defaultRootCertificatesDirName,
    );

    return {
        certificatesDirPath,
        leafCertificateNames: await readCertificateNames(certificatesDirPath),
        rootCertificateNames: await readCertificateNames(rootCertificatesDirPath),
        rootCertificatesDirPath,
    };
}

/**
 * Run the list command.
 *
 * @category Internal
 */
export async function runListCertificatesCommand(this: void, params: Readonly<ListCommandParams>) {
    const certificateList = await listCertificates(params);

    log.info(
        [
            ...describeCertificates({
                dirPath: certificateList.rootCertificatesDirPath,
                label: 'Root certificates',
                names: certificateList.rootCertificateNames,
            }),
            ...describeCertificates({
                dirPath: certificateList.certificatesDirPath,
                label: 'Leaf certificates',
                names: certificateList.leafCertificateNames,
            }),
        ].join('\n'),
    );
}

/** A missing directory means no certificates have been saved in it yet. */
async function readCertificateNames(dirPath: string) {
    const fileNames = await wrapInTry(async () => await readdir(dirPath), {
        fallbackValue: [],
    });

    return fileNames
        .map((fileName) => extractExtension(fileName))
        .filter((extracted) => extracted.extension === '.crt')
        .map((extracted) => extracted.basename)
        .toSorted();
}

function describeCertificates({
    dirPath,
    label,
    names,
}: Readonly<{
    dirPath: string;
    label: string;
    names: ReadonlyArray<string>;
}>) {
    if (!names.length) {
        return [`No ${label.toLowerCase()} in ${dirPath}.`];
    }

    return [
        `${label} in ${dirPath}:`,
        ...names.map((name) => `    ${name}`),
    ];
}
