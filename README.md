# dsm-certtool

A super small tool with one purpose: importing new certificates into Synology DSM.

Usage:

```
export SYNO_PASSWORD=password
dsm-certtool -url http://storage:5000 -username username -cert tls.crt -key tls.key
```

The tool will automatically find and update existing certs based on the common
name. It will also split the provided certificate into a leaf and N intermediate
certs for compatibility with the Synology DSM API.

This is ideal for use with automatically provisioned certs from `cert-manager`,
but was designed to be agnostic to how you issue your certs.