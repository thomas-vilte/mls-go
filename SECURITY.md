# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2.0 | :x:                |

This is beta software. Security updates are provided for the latest minor version (0.2.x).

## Reporting a Vulnerability

**Important:** Do not open public issues for security vulnerabilities.

Please report security issues to: **viltetomas2003@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

I'll respond within 7 days with:
- Confirmation of receipt
- Initial assessment
- Timeline for fix

## What to expect

1. **Within 7 days:** Initial response and assessment
2. **Within 30 days:** Fix developed and tested
3. **After fix:** Coordinated disclosure (if you agree)

## Known limitations

This is beta software. Some known limitations:

- Not all RFC 9420 features implemented
- TreeKEM operations incomplete
- External senders not implemented
- API may change between versions

These are not vulnerabilities - they're documented gaps in implementation.

## Security best practices

When using mls-go:

1. **Always use latest version** - Security fixes in latest release
2. **Validate KeyPackages** - Don't trust unvalidated key packages
3. **Protect private keys** - Use secure storage
4. **Zero secrets after use** - Clear memory containing secrets
5. **Use secure random** - Ensure crypto/rand is properly seeded
6. **Monitor for updates** - Watch releases for security patches

## Cryptographic assumptions

mls-go relies on:
- Go standard library crypto (audited)
- golang.org/x/crypto for HPKE (audited)
- RFC 9420, RFC 9180, RFC 5869 specifications

If you find issues in these dependencies, report to respective maintainers.

## Disclaimer

This is beta software. Use at your own risk. Not recommended for production handling sensitive data until v1.0.0.

For production use today, consider [OpenMLS](https://github.com/openmls/openmls) (Rust, production-ready).
