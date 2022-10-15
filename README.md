# dsm-certtool

A super small tool with one purpose: importing new certificates into Synology DSM.

Usage:

```
dsm-certtool -url http://storage:5000 -username username -password password -cert tls.crt -key tls.key
```

The tool will automatically find and update existing certs based on the common
name. It will also split the provided certificate into a leaf and N intermediate
certs for compatibility with the Synology DSM API.

This is ideal for use with automatically provisioned certs from `cert-manager`,
but was designed to be agnostic to how you issue your certs.