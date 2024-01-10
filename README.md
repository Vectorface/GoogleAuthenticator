Google Authenticator (TOTP)
===========================

![Build Status](https://github.com/Vectorface/GoogleAuthenticator/workflows/Test/badge.svg)

This is a fork of https://github.com/PHPGangsta/GoogleAuthenticator with the following changes:

- Uses https://github.com/endroid/qr-code to generate QR code data URIs
- No longer generates Google's Chart API to make QR code links
- Uses namespacing
- Augmented test coverage to 100%
- Bumped minimum PHP version to 8.1

Original License:
-----------------

* Copyright (c) 2012-2016, [http://www.phpgangsta.de](http://www.phpgangsta.de)
* Author: Michael Kliewe, [@PHPGangsta](http://twitter.com/PHPGangsta) and [contributors](https://github.com/PHPGangsta/GoogleAuthenticator/graphs/contributors)
* Licensed under the BSD License.

Description:
------------

This PHP class can be used to interact with the Google Authenticator mobile app for 2-factor-authentication. This class
can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret. It implements TOTP 
according to [RFC6238](https://tools.ietf.org/html/rfc6238)

For a secure installation you have to make sure that used codes cannot be reused (replay-attack). You also need to
limit the number of verifications, to fight against brute-force attacks. For example you could limit the amount of
verifications to 10 tries within 10 minutes for one IP address (or IPv6 block). It depends on your environment.

Usage:
------

See following example:

```php
<?php
require_once 'vendor/autoload.php';

use Vectorface\GoogleAuthenticator;

$ga = new GoogleAuthenticator();
$secret = $ga->createSecret();
echo "Secret is: {$secret}\n\n";

$qrCodeUrl = $ga->getQRCodeUrl('Blog', $secret);
echo "PNG Data URI for the QR-Code: {$qrCodeUrl}\n\n";

$oneCode = $ga->getCode($secret);
echo "Checking Code '$oneCode' and Secret '$secret':\n";

// 2 = 2*30sec clock tolerance
$checkResult = $ga->verifyCode($secret, $oneCode, 2);
if ($checkResult) {
    echo 'OK';
} else {
    echo 'FAILED';
}
```
Running the script provides output similar to:
```
Secret is: OQB6ZZGYHCPSX4AK

PNG Data URI for the QR-Code: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAARgAAAEYCAIAAAAI[snipped]

Checking Code '848634' and Secret 'OQB6ZZGYHCPSX4AK':
OK
```

Installation:
-------------

- Use [Composer](https://getcomposer.org/doc/01-basic-usage.md) to
  install the package

```composer require vectorface/googleauthenticator```

Run Tests:
----------

- All tests are inside `tests` folder.
- Execute `composer install` to prepare your environment.
- Run `composer test` from the project root directory.
