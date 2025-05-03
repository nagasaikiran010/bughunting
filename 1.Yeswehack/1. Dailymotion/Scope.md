> URL: https://yeswehack.com/programs/dailymotion-public-bug-bounty

Here's your data organized into a clean table format:

|Scope|Type|Asset Value|
|---|---|---|
|*.dailymotion.com|Web application|Low|
|*.api.dailymotion.com|API|Low|
|developer.dailymotion.com|Web application|Low|
|*.dmcdn.net|Web application|Low|
|[Google Play - Dailymotion App](https://play.google.com/store/apps/details?id=com.dailymotion.dailymotion&hl=fr&gl=US)|Mobile application Android|Low|
|[App Store - Dailymotion App](https://apps.apple.com/fr/app/dailymotion/id336978041)|Mobile application IOS|Low|
|ifttt-adaptor.pub.kube.dm.gg|API|Low|
|AS41690|Other|Low|
|dmxleo.com|API|Low|
|*.dm.gg|Web application|Low|
|Google Cloud Platform Instances|Other|Low|

## Vulnerability types

### Qualifying vulnerabilities

- Any design or implementation issue that is reproducible and substantially affects the security of Dailymotion users is likely to qualify

- Remote Code Execution (RCE)

- SQL injections

- OS Command Injections

- XML eXternal Entities injection (XXE)

- Server Side Request Forgery (SSRF)

- Insecure direct object reference (IDOR)

- Insecure object deserialization

- Authentication bypass

- Unprotected APIs

- Application logic flaws that can be leveraged with security impact against Dailymotion or our users

- Open redirects (except `autodiscover`)

- XSS (see note in Rewards)

- Personal data leakage

- Exposed secrets, credentials or sensitive information on an asset under our control and affecting at least one of our scopes

### Non-qualifying vulnerabilities

- CSRF

- Attacks requiring physical access to a user's device

- Attacks requiring access to the network traffic (e.g. manipulation of DNS queries or responses)

- Vulnerabilities affecting users of outdated or unpatched browsers and platforms

- Attacks which require that the user's device is compromised (malware, jailbreak, etc)

- Information disclosure not directly relating to a demonstrated issue

- Password and account recovery policies, such as reset link expiration or password complexity requirements

- Missing security headers which do not directly lead to a vulnerability

- HttpOnly and Secure cookie flags

- HTTPS configuration derivations from "state of the art" (such as HSTS settings, Secure flag for cookies, "weak" TLS ciphers, etc)

- Clickjacking on static websites

- XSS attacks via POST requests, or self-XSS (unless you provide a PoC that shows impact on other Dailymotion users)

- XSS or XSRF that requires header injection

- Content spoofing / text injection

- Denial of service attacks

- Absence of rate-limiting (or disagreement over existing thresholds)

- Use of a known-vulnerable library or software (unless you can provide relevant exploit PoC)

- Issues related to software or protocols not under Dailymotion control

- Reports from automated tools or scans

- Reports of spam

- Social engineering of Dailymotion (current or past) staff or contractors

- Any physical attempts against Dailymotion's property or data centers

- Concerns related to email domain authentication (SPF, DMARC, DKIM, etc)

- User enumeration (including administrative accounts)

- Nonreproducible issues of any sort

- Exposed secrets, credentials or information on an asset under our control that are not applicable to the program’s scope