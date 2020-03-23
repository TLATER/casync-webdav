# casync-webdav

A store synchronizer for
[casync](https://www.github.com/systemd/casync) that uploads and
downloads casync stores and their indexes to webdav hosts, with basic
http/s authentication support.

This is still quite WIP, for now only uploads are supported.

## Usage

```
casync-webdav 0.1.0
Upload chunks from a casync-based store to a remote webdav host

USAGE:
    casync-webdav [OPTIONS] <index> [webdav-url]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -k, --certificate-password <certificate-password>    The password for the client certificate
    -c, --client-certificate <client-certificate>        The client certificate to use for authentication to the remote
    -p, --password <password>                            The password to use with the username
    -s, --store <store>                                  The store to load chunks from [default: default.castr]
    -r, --store-root <store-root>                        The path to upload to on the webdav host [default: /]
    -u, --username <username>                            The user for authentication to the remote

ARGS:
    <index>         The index whose chunks to upload
    <webdav-url>    The webdav host to upload to; If unset, chunks will be listed instead
```
