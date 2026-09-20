/**
 * The commands that this package supports.
 *
 * @category Internal
 */
export enum CertVirCommand {
    /** Create a root certificate for signing child certificates. */
    Root = 'root',
    /**
     * Create a leaf certificate (for a website, for example) using a root certificate.
     *
     * When running the CLI directly, this is the default command.
     */
    Leaf = 'leaf',
    /** Trust a root certificate. */
    Trust = 'trust',
}
