# Google Authenticator (TOTP)

![构建状态](https://github.com/Vectorface/GoogleAuthenticator/workflows/Test/badge.svg)

**中文** | [English](./README.md)

一个与 Google Authenticator 移动应用兼容的 PHP 双因素认证（2FA）库。
它可以生成密钥、生成并校验一次性验证码，并将密钥渲染为可扫描的二维码 —— 按照
[RFC 6238](https://tools.ietf.org/html/rfc6238) 规范实现 TOTP。

本项目是 [PHPGangsta/GoogleAuthenticator](https://github.com/PHPGangsta/GoogleAuthenticator) 的分支，包含以下改动：

- 使用 [endroid/qr-code](https://github.com/endroid/qr-code) 生成二维码数据 URI
- 不再依赖 Google Chart API 生成二维码链接
- 使用命名空间
- 测试覆盖率提升至 100%
- 最低 PHP 版本提升至 8.2

## 安装

通过 [Composer](https://getcomposer.org/doc/01-basic-usage.md) 安装：

```bash
composer require vectorface/googleauthenticator
```

## 快速开始

```php
<?php
require_once 'vendor/autoload.php';

use Vectorface\GoogleAuthenticator;

$ga = new GoogleAuthenticator();

// 1. 创建密钥并分发给用户
$secret = $ga->createSecret();
echo "密钥是: {$secret}\n\n";

// 2. 将密钥渲染为二维码（PNG 数据 URI）供用户扫描
$qrCodeUrl = $ga->getQRCodeUrl('Admin', $secret, 'Blog');
echo "二维码的 PNG 数据 URI: {$qrCodeUrl}\n\n";

// 3. 校验用户输入的一次性验证码
$oneCode = $ga->getCode($secret);
echo "检查验证码 '$oneCode' 和密钥 '$secret':\n";

// discrepancy = 2 表示允许 ±2 × 30 秒的时钟偏差
$checkResult = $ga->verifyCode($secret, $oneCode, 2);
echo $checkResult ? 'OK' : 'FAILED';
```

运行脚本会得到类似以下的输出：

```
密钥是: OQB6ZZGYHCPSX4AK

二维码的 PNG 数据 URI: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAARgAAAEYCAIAAAAI[已截断]

检查验证码 '848634' 和密钥 'OQB6ZZGYHCPSX4AK':
OK
```

## 安全注意事项

### 防止重放攻击

同一个 TOTP 验证码绝不能被接受两次。`verifyCode()` 接受一个可选的引用参数，
用于接收匹配成功的时间片。按照 [RFC 6238 第 5.2 节](https://tools.ietf.org/html/rfc6238#section-5.2)
的要求，请为每个用户持久化最后一次接受的时间片，并拒绝任何匹配时间片小于或等于该存储值的验证码：

```php
$matchedTimeSlice = null;
if ($ga->verifyCode($secret, $oneCode, 2, $matchedTimeSlice)) {
    if ($matchedTimeSlice <= $user->lastUsedTimeSlice) {
        // 验证码已被使用：拒绝以防止重放攻击
    } else {
        $user->lastUsedTimeSlice = $matchedTimeSlice; // 持久化该值
        // 验证码通过
    }
}
```

### 限制验证频率

为防御暴力破解攻击，请限制验证尝试次数。例如，可以将单个 IP 地址（或 IPv6 网段）
的验证限制为 10 分钟内最多 10 次尝试 —— 请根据实际环境调整。

## 进阶用法

### 自定义验证码长度

验证码默认为 6 位，支持 6 到 8 位（RFC 4226）：

```php
$ga = (new GoogleAuthenticator())->setCodeLength(8);
```

### 构建 otpauth:// URI

如需完全控制配置 URI（算法、位数、周期、HOTP 计数器等），可使用链式的 `UriBuilder`：

```php
$uri = $ga->getUriBuilder()
    ->issuer('Blog')
    ->account('Admin')
    ->secret($secret)
    ->getUri(); // otpauth://totp/Blog:%20Admin?secret=...&issuer=Blog
```

## 运行测试

所有测试位于 `tests` 文件夹内。

```bash
composer install
composer test
```

## 许可证

基于 [BSD 许可证](./LICENSE.md)授权。

原始项目：

- 版权所有 (c) 2012-2016, [http://www.phpgangsta.de](http://www.phpgangsta.de)
- 作者：Michael Kliewe, [@PHPGangsta](http://twitter.com/PHPGangsta) 及[贡献者](https://github.com/PHPGangsta/GoogleAuthenticator/graphs/contributors)
