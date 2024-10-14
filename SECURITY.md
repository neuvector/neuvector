# Security Policy

SUSE Rancher is deeply committed to safeguarding the security of our products,
and endeavors to resolve security issues in a timely manner.

We extend our heartfelt thanks to the security researchers and users who
diligently report vulnerabilities. Your invaluable contributions enhance our
ability to improve our systems and protect our user community.

We go through all reported security issues, reviewing them with the project's
maintainers and coordinating the fixes and disclosures. We credit all accepted
reports from users and security researchers in our [Security
Advisories](https://github.com/neuvector/neuvector/security/advisories).

## Reporting a vulnerability

Please before reporting a vulnerability, make sure it impacts a [supported
version](#supported-versions).

### What types of issue to report

This reporting channel focuses on bugs with potential security impact on
products within the SUSE Rancher ecosystem. Example of valid reports:

- Cross-site script (XSS) on the user interface.
- Privilege escalation through RBAC and permissions.
- Code execution in the container or host OS.

If you are unsure, check the types of issues NOT to report below.

### What types of issue NOT to report

Some issues are outside of the scope of this channel, and therefore should not
be reported:

- CVEs that were found by CVE scanners (e.g. Trivy, Snyk). Public CVEs do not
  need to be reported as they are fixed as part of the development process.
- Improvements or questions on the security hardening guides. These should be
  reported as a new [docs
issue](https://github.com/neuvector/docs/issues/new/choose).
- Issues or bugs that aren't security related. These should be reported as a new
  [issue](https://github.com/neuvector/neuvector/issues/new/choose).
- Issues with mirrored container images, instead please report them via the
  security channels of the specific upstream project.
- Issues that require the user to disable security features or downgrade the
  security of its environment in order for the vulnerability to be exploited.
- Issues that can only be exploited by the administrator itself (after all, the
  admin is already a privileged user and implicitly trusted).
- Issues regarding missing HTTP headers or exposure of versions in HTTP headers.
- Vulnerabilities affecting directly a user or customer environment. Such
  vulnerabilities must be reported directly to the affected user/customer. Be
advised that such reports can constitute law infringement under certain
jurisdictions.

If going through all the examples above you are still in doubt, please go ahead
and use this channel. After all, it's better be safe than sorry.

## Supported versions

Please review our [support maintenance and
terms](https://www.suse.com/lifecycle/#neuvector) to view the current support
lifecycle.

## Reporting a vulnerability

To report a security vulnerability, email `security-rancher@suse.com`. You can
optionally use the GPG key `rsa4096/C9DF50BDAC351DA9` for encrypted
communication.

We currently do not have a bug bounty rewards program in place, and nor do we
offer swags. However, we genuinely appreciate the vigilance and expertise of our
user community in helping us maintain the highest security standards.

We strive to acknowledge receiving submissions within 5 working days, please
wait until that time has past before asking for a status update.

The information contained in your report must be treated as embargoed and must
not be shared publicly, unless explicitly agreed with us first. This is to
protect the SUSE Rancher ecosystem users and enable us to follow through our
coordinated disclosure process. The information shall be kept embargoed until a
fix is released.

### What information to provide

Feel free to get in touch in whatever way works best for you! However, if you're
able to include the information below in your report, that would be incredibly
helpful and much appreciated:

- Product name and version where the issue was observed. If the issue was
  observed on the source code, the link to the specific code in GitHub instead.
  - Please include the versions of the host OS, Kubernetes etc.
- Description of the problem.
- Type of the issue and impact when exploited.
- Steps to reproduce or a proof of concept.

The more information you provide, the faster we will be able to reproduce the
issue and address your concerns more effectively.

### GPG Key - `security-rancher@suse.com`

```pgp
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
ArCzVjxOM8JhL941OADyL1A=
=l4yT
-----END PGP PUBLIC KEY BLOCK-----
```
