# cert-vir

A simple CLI and API for creating a root SSL certificate and leaf certificates from it.

## Install

```sh
npm i cert-vir
```

globally:

```sh
npm i -g cert-vir
```

## Usage

### CLI

-   `cert-vir root`: create a root certificate.
-   `cert-vir leaf`: create a leaf certificate, signed by the root certificate.
-   `sudo cert-vir trust`: trust the root certificate on this machine. (macOS only currently. Requires `sudo`.)

Any missing value is prompted for. Pass it as a flag to skip its prompt:

```sh
cert-vir leaf --certificate-file-name my-site --domain-names localhost --ip-addresses 127.0.0.1
```

Run `cert-vir <command> --help` for all flags.

Certificates are saved in `~/.config/cert-vir/` unless `--certificates-dir-path` is set.

To renew a leaf certificate, run `cert-vir leaf` again with the same file name. Its key is kept.

### API

For API usage, see the included TS types and the reference docs here: https://electrovir.github.io/cert-vir
