<?php

namespace Tests\Vectorface\OtpAuth;

use PHPUnit\Framework\TestCase;
use Vectorface\GoogleAuthenticator;
use Vectorface\OtpAuth\Base32;
use Vectorface\OtpAuth\Parameters\Type;
use Vectorface\OtpAuth\UriBuilder;
use Vectorface\OtpAuth\Parameters\Algorithm;

class UriBuilderTest extends TestCase
{
    /**
     * @test
     */
    public function synopsis()
    {
        /* URI builder basic usage: Provide an account name and secret */
        $uriBuilder = (new UriBuilder())
            ->account("MyAcct")
            ->secret("FOO");

        /* The builder can generate otpauth URLs */
        $this->assertEquals("otpauth://totp/MyAcct?secret=FOO", "$uriBuilder");

        /* ... or QR codes as data URIs */
        $this->assertStringStartsWith("data:image/png;base64,", $uriBuilder->getQRCodeDataUri());

        /* It is also possible to construct complex OTP URIs, including HOTP */
        $uriBuilder = (new UriBuilder())
            ->type(Type::HOTP)
            ->account("My Account")
            ->issuer("My Company")
            ->secret("Raw Secret", true)
            ->algorithm(Algorithm::SHA256)
            ->digits(8)
            ->counter(123);

        $this->assertEquals('otpauth://hotp/My%20Company:%20My%20Account?secret=KJQXOICTMVRXEZLU&issuer=My%20Company&algorithm=SHA256&digits=8&counter=123', "$uriBuilder");
    }

    /**
     * Each case pairs a configured builder with the otpauth URI it must produce.
     * Every secret here is a valid base32 (rfc3548) string, as required by the spec.
     */
    public function validSecretUriProvider(): array
    {
        return [
            'TOTP default, 16-char secret' => [
                (new UriBuilder())
                    ->account("alice@example.com")
                    ->secret("JBSWY3DPEHPK3PXP"),
                "otpauth://totp/alice%40example.com?secret=JBSWY3DPEHPK3PXP",
            ],
            'TOTP full params, 32-char secret' => [
                (new UriBuilder())
                    ->account("alice")
                    ->issuer("Example Inc")
                    ->secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
                    ->algorithm(Algorithm::SHA512)
                    ->digits(6)
                    ->period(60),
                "otpauth://totp/Example%20Inc:%20alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20Inc&algorithm=SHA512&digits=6&period=60",
            ],
            'HOTP, counter 0' => [
                (new UriBuilder())
                    ->type(Type::HOTP)
                    ->account("bob")
                    ->secret("JBSWY3DPEHPK3PXP")
                    ->counter(0),
                "otpauth://hotp/bob?secret=JBSWY3DPEHPK3PXP",
            ],
            'TOTP, raw secret base32-encoded' => [
                (new UriBuilder())
                    ->account("carol")
                    ->secret("Raw Secret", true),
                "otpauth://totp/carol?secret=KJQXOICTMVRXEZLU",
            ],
        ];
    }

    /**
     * @dataProvider validSecretUriProvider
     */
    public function testBuildsUriWithValidSecret(UriBuilder $builder, string $expected): void
    {
        $this->assertEquals($expected, (string)$builder);

        // The secret embedded in the URI must be a decodable base32 string.
        parse_str(parse_url((string)$builder, PHP_URL_QUERY), $query);
        $this->assertNotNull(Base32::decode($query['secret']), "embedded secret is not valid base32");
    }

    /**
     * A secret produced by createSecret() must be a valid base32 string that survives
     * the round-trip through the URI builder and back out via decode().
     */
    public function testCreateSecretProducesUsableUri(): void
    {
        $secret = (new GoogleAuthenticator())->createSecret();

        $uri = (string)(new UriBuilder())->account("dave")->secret($secret);
        $this->assertStringContainsString("secret={$secret}", $uri);

        parse_str(parse_url($uri, PHP_URL_QUERY), $query);
        $this->assertSame($secret, $query['secret']);
        $this->assertNotNull(Base32::decode($query['secret']));
    }

    public function testInvalidType()
    {
        $this->expectException(\TypeError::class);
        (new UriBuilder())
            ->type("foo");
    }

    public function testInvalidAlgorithm()
    {
        $this->expectException(\TypeError::class);
        (new UriBuilder())
            ->algorithm("foo");
    }

    public function testMissingSecret()
    {
        $this->expectException(\DomainException::class);
        (new UriBuilder())
            ->getUri();
    }

    public function testMissingCounter()
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage("Counter is a required HOTP parameter");
        (new UriBuilder())
            ->secret("FOO")
            ->type(Type::HOTP)
            ->getUri();
    }

    public function testInvalidCounterUsage()
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage("Counter parameter does not apply to TOTP");
        (new UriBuilder())
            ->secret("FOO")
            ->type(Type::TOTP)
            ->counter(123)
            ->getUri();
    }

    public function testInvalidPeriodUsage()
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage("Period parameter does not apply to HOTP");
        (new UriBuilder())
            ->secret("FOO")
            ->type(Type::HOTP)
            ->counter(0)
            ->period(30)
            ->getUri();
    }

    /**
     * @dataProvider invalidArgumentsProvider
     */
    public function testInvalidArguments(string $message, int $digits, int $counter, int $period)
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        (new UriBuilder())
            ->digits($digits)
            ->period($period)
            ->counter($counter);
    }

    public function invalidArgumentsProvider()
    {
        return [
            "Digits must be positive" => ["Number of digits must be 6 or 8", 5, 0, 1],
            "Counter must be positive" => ["Counter must be an integer greater than or equal to zero", 6, -1, 1],
            "Period must be positive" => ["Period must be an integer greater than zero", 6, 0, 0],
        ];
    }
}
