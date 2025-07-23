Google Authenticator (TOTP)
===========================

![构建状态](https://github.com/Vectorface/GoogleAuthenticator/workflows/Test/badge.svg)

**中文** | [English](./README.md)

这是 https://github.com/PHPGangsta/GoogleAuthenticator 的一个分支，包含以下更改：

- 使用 https://github.com/endroid/qr-code 生成二维码数据 URIs
- 不再生成 Google 的 Chart API 来制作二维码链接
- 使用命名空间
- 将测试覆盖率增加到 100%
- 将最低 PHP 版本提升到 8.2

原始许可证：
-----------------

* 版权所有 (c) 2012-2016, [http://www.phpgangsta.de](http://www.phpgangsta.de)
* 作者：Michael Kliewe, [@PHPGangsta](http://twitter.com/PHPGangsta) 和 [贡献者](https://github.com/PHPGangsta/GoogleAuthenticator/graphs/contributors)
* 根据 BSD 许可证授权。

描述：
------------

这个 PHP 类可以用来与 Google Authenticator 移动应用进行双重因素认证交互。该类可以生成密钥、生成代码、验证代码并提供用于扫描密钥的二维码。它实现了根据 [RFC6238](https://tools.ietf.org/html/rfc6238) 的 TOTP。

为了您能安全安装，您必须确保使用的代码不能被重复使用（重放攻击）。您还需要限制验证次数，以对抗暴力攻击。例如，您可以将一个 IP 地址（或 IPv6 块）的验证次数限制为 10 分钟内 10 次尝试。这取决于您的环境。

用法：
------

请参见以下示例：

```php
<?php
require_once 'vendor/autoload.php';

use Vectorface\GoogleAuthenticator;

$ga = new GoogleAuthenticator();
$secret = $ga->createSecret();
echo "密钥是: {$secret}\n\n";

$qrCodeUrl = $ga->getQRCodeUrl('Admin', $secret, 'Blog');
echo "二维码的 PNG 数据 URI: {$qrCodeUrl}\n\n";

$oneCode = $ga->getCode($secret);
echo "检查代码 '$oneCode' 和密钥 '$secret':\n";

// 2 = 2*30秒的时钟容差
$checkResult = $ga->verifyCode($secret, $oneCode, 2);
if ($checkResult) {
    echo 'OK';
} else {
    echo 'FAILED';
}
```
运行脚本会提供类似以下的输出：
```
密钥是: OQB6ZZGYHCPSX4AK

二维码的 PNG 数据 URI: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAARgAAAEYCAIAAAAI[已截断]

检查代码 '848634' 和密钥 'OQB6ZZGYHCPSX4AK':
OK
```

安装：
-------------

- 使用 [Composer](https://getcomposer.org/doc/01-basic-usage.md) 安装包

```composer require vectorface/googleauthenticator```

运行测试：
----------

- 所有测试都在 `tests` 文件夹内。
- 执行 `composer install` 来准备您的环境。
- 从项目根目录运行 `composer test`。