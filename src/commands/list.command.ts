// cspell:words nameopt noout

import {
    extractExtension,
    log,
    replaceExtension,
    shellQuote,
    wrapInTry,
    type PartialWithUndefined,
} from '@augment-vir/common';
import {runShellCommand} from '@augment-vir/node';
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
 * Details read out of a single certificate. Every field except `certificateFileName` is empty when
 * the certificate cannot be read or simply does not carry that field.
 *
 * @category Internal
 */
export type CertificateInfo = {
    /**
     * The certificate's file name without its extension, in the format that the leaf command's
     * `certificateFileName` param expects.
     */
    certificateFileName: string;
    /** The certificate's own common name (CN). */
    commonName: string;
    domainNames: string[];
    ipAddresses: string[];
    /**
     * The common name (CN) of the certificate that signed this one. A self-signed root certificate
     * issues itself, so this matches its own `commonName`.
     */
    issuerCommonName: string;
};

/**
 * Output of {@link listCertificates}.
 *
 * @category Internal
 */
export type CertificateList = {
    certificatesDirPath: string;
    /** Sorted by file name. */
    leafCertificates: CertificateInfo[];
    /** Sorted by file name. */
    rootCertificates: CertificateInfo[];
    rootCertificatesDirPath: string;
};

/**
 * Read every certificate saved in the given certificates directory. Certificates are identified by
 * their `'.crt'` files, so a key without a certificate is not listed.
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
        leafCertificates: await readCertificates(certificatesDirPath),
        rootCertificates: await readCertificates(rootCertificatesDirPath),
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
                certificates: certificateList.rootCertificates,
                dirPath: certificateList.rootCertificatesDirPath,
                label: 'Root certificates',
            }),
            ...describeCertificates({
                certificates: certificateList.leafCertificates,
                dirPath: certificateList.certificatesDirPath,
                label: 'Leaf certificates',
            }),
        ].join('\n'),
    );
}

/** A missing directory means no certificates have been saved in it yet. */
async function readCertificates(dirPath: string) {
    const fileNames = await wrapInTry(async () => await readdir(dirPath), {
        fallbackValue: [],
    });

    return await Promise.all(
        fileNames
            .map((fileName) => extractExtension(fileName))
            .filter((extracted) => extracted.extension === '.crt')
            .map((extracted) => extracted.basename)
            .toSorted()
            .map(async (certificateFileName) => {
                return await readCertificate({
                    certificateFileName,
                    dirPath,
                });
            }),
    );
}

async function readCertificate({
    certificateFileName,
    dirPath,
}: Readonly<{
    certificateFileName: string;
    dirPath: string;
}>): Promise<CertificateInfo> {
    /**
     * `RFC2253` is the only `nameopt` that escapes a comma inside a value, so it is the only one
     * whose output can be split back apart without guessing where each field ends.
     */
    const crtFilePath = join(
        dirPath,
        replaceExtension({
            newExtension: '.crt',
            path: certificateFileName,
        }),
    );
    const {stdout} = await runShellCommand(
        `openssl x509 -in ${shellQuote(crtFilePath)} -noout -subject -issuer -ext subjectAltName -nameopt RFC2253`,
    );
    const lines = stdout.split('\n');
    const altNames = (
        lines.find((line) => {
            return (
                line.trimStart().startsWith('DNS:') || line.trimStart().startsWith('IP Address:')
            );
        }) || ''
    )
        .split(',')
        .map((altName) => altName.trim());

    return {
        certificateFileName,
        commonName: extractCommonName({
            lines,
            linePrefix: 'subject=',
        }),
        domainNames: extractAltNames({
            altNames,
            prefix: 'DNS:',
        }),
        ipAddresses: extractAltNames({
            altNames,
            prefix: 'IP Address:',
        }),
        issuerCommonName: extractCommonName({
            lines,
            linePrefix: 'issuer=',
        }),
    };
}

function extractCommonName({
    linePrefix,
    lines,
}: Readonly<{
    linePrefix: string;
    lines: ReadonlyArray<string>;
}>) {
    const matchedLine = lines.find((line) => line.startsWith(linePrefix)) || '';
    const commonName = /(?:^|,)CN=((?:[^,\\]|\\.)*)/.exec(
        matchedLine.slice(linePrefix.length),
    )?.[1];

    return (commonName || '').replaceAll(/\\(.)/g, '$1');
}

function extractAltNames({
    altNames,
    prefix,
}: Readonly<{
    altNames: ReadonlyArray<string>;
    prefix: string;
}>) {
    return altNames
        .filter((altName) => altName.startsWith(prefix))
        .map((altName) => altName.slice(prefix.length));
}

function describeCertificates({
    certificates,
    dirPath,
    label,
}: Readonly<{
    certificates: ReadonlyArray<CertificateInfo>;
    dirPath: string;
    label: string;
}>) {
    if (!certificates.length) {
        return [`No ${label.toLowerCase()} in ${dirPath}.`];
    }

    return [
        `${label} in ${dirPath}:`,
        ...certificates.flatMap((certificate) => describeCertificate(certificate)),
    ];
}

function describeCertificate(certificate: Readonly<CertificateInfo>) {
    return [
        `    ${certificate.certificateFileName}`,
        ...describeField({
            label: 'common name',
            value: certificate.commonName,
        }),
        ...describeField({
            label: 'signed by',
            /** A self-signed root certificate would just repeat its own common name here. */
            value:
                certificate.issuerCommonName === certificate.commonName
                    ? ''
                    : certificate.issuerCommonName,
        }),
        ...describeField({
            label: 'domain names',
            value: certificate.domainNames.join(', '),
        }),
        ...describeField({
            label: 'ip addresses',
            value: certificate.ipAddresses.join(', '),
        }),
    ];
}

function describeField({
    label,
    value,
}: Readonly<{
    label: string;
    value: string;
}>) {
    if (!value) {
        return [];
    }

    return [`        ${label}: ${value}`];
}
