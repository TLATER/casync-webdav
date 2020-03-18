# casync-webdav

A store synchronizer for
[casync](https://www.github.com/systemd/casync) that uploads and
downloads casync stores and their indexes to webdav hosts, with basic
http/s authentication support.

This is still quite WIP, for now only uploads are supported.

## Usage

```
casync-webdav 0.1.0

USAGE:
    casync-webdav [OPTIONS] <index> <store> <webdav-url> <store-path>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -k, --certificate-password <certificate-password>
    -c, --client-certificate <client-certificate>
    -p, --password <password>
    -u, --username <username>

ARGS:
    <index>
    <store>
    <webdav-url>
    <store-path>
```
