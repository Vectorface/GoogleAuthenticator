# Google Authenticator (TOTP)

![Build Status](https://github.com/Vectorface/GoogleAuthenticator/workflows/Test/badge.svg)

**English** | [中文](./README.zh-CN.md)

A PHP library for two-factor authentication (2FA) compatible with the Google Authenticator mobile app.
It can generate secrets, generate and verify one-time codes, and render the secret as a scannable
QR code — implementing TOTP as specified in [RFC 6238](https://tools.ietf.org/html/rfc6238).

This is a fork of [PHPGangsta/GoogleAuthenticator](https://github.com/PHPGangsta/GoogleAuthenticator) with the following changes:

- Uses [endroid/qr-code](https://github.com/endroid/qr-code) to generate QR code data URIs
- No longer relies on Google's Chart API for QR code links
- Uses namespacing
- Test coverage raised to 100%
- Minimum PHP version bumped to 8.2

## Installation

Install via [Composer](https://getcomposer.org/doc/01-basic-usage.md):

```bash
composer require vectorface/googleauthenticator
```

## Quick Start

```php
<?php
require_once 'vendor/autoload.php';

use Vectorface\GoogleAuthenticator;

$ga = new GoogleAuthenticator();

// 1. Create a secret and share it with the user
$secret = $ga->createSecret();
echo "Secret is: {$secret}\n\n";

// 2. Render the secret as a QR code (PNG data URI) for the user to scan
$qrCodeUrl = $ga->getQRCodeUrl('Admin', $secret, 'Blog');
echo "PNG Data URI for the QR-Code: {$qrCodeUrl}\n\n";

// 3. Verify the one-time code entered by the user
$oneCode = $ga->getCode($secret);
echo "Checking Code '$oneCode' and Secret '$secret':\n";

// discrepancy = 2 allows a clock tolerance of ±2 × 30 seconds
$checkResult = $ga->verifyCode($secret, $oneCode, 2);
echo $checkResult ? 'OK' : 'FAILED';
```

Running the script produces output similar to:

```
Secret is: OQB6ZZGYHCPSX4AK

PNG Data URI for the QR-Code: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAARgAAAEYCAIAAAAI[snipped]

Checking Code '848634' and Secret 'OQB6ZZGYHCPSX4AK':
OK
```

## Security Considerations

### Preventing replay attacks

A TOTP code must never be accepted twice. `verifyCode()` accepts an optional by-reference
parameter that receives the time slice which matched. As required by
[RFC 6238 section 5.2](https://tools.ietf.org/html/rfc6238#section-5.2), persist the last
accepted time slice per user and refuse any code that matches a slice less than or equal to
the stored value:

```php
$matchedTimeSlice = null;
if ($ga->verifyCode($secret, $oneCode, 2, $matchedTimeSlice)) {
    if ($matchedTimeSlice <= $user->lastUsedTimeSlice) {
        // Code already used: reject to prevent a replay attack
    } else {
        $user->lastUsedTimeSlice = $matchedTimeSlice; // persist this value
        // Code accepted
    }
}
```

### Rate limiting

To defend against brute-force attacks, limit the number of verification attempts. For example,
allow at most 10 tries within 10 minutes per IP address (or IPv6 block) — adjust to fit your
environment.

## Advanced Usage

### Custom code length

Codes are 6 digits by default. Lengths of 6 to 8 digits are supported (RFC 4226):

```php
$ga = (new GoogleAuthenticator())->setCodeLength(8);
```

### Building otpauth:// URIs

For full control over the provisioning URI (algorithm, digits, period, HOTP counter, etc.),
use the fluent `UriBuilder`:

```php
$uri = $ga->getUriBuilder()
    ->issuer('Blog')
    ->account('Admin')
    ->secret($secret)
    ->getUri(); // otpauth://totp/Blog:%20Admin?secret=...&issuer=Blog
```

## Running Tests

All tests live in the `tests` folder.

```bash
composer install
composer test
```

## License

Licensed under the [BSD License](./LICENSE.md).

Original work:

- Copyright (c) 2012-2016, [http://www.phpgangsta.de](http://www.phpgangsta.de)
- Author: Michael Kliewe, [@PHPGangsta](http://twitter.com/PHPGangsta) and [contributors](https://github.com/PHPGangsta/GoogleAuthenticator/graphs/contributors)
