<?php

namespace Tests\Vectorface\OtpAuth;

use PHPUnit\Framework\TestCase;
use Vectorface\OtpAuth\Paramters\Type;
use Vectorface\OtpAuth\UriBuilder;
use Vectorface\OtpAuth\Paramters\Algorithm;

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

        $this->assertEquals('otpauth://hotp/My%20Company:%20My%20Account?secret=SBXATFDSFU&issuer=My%20Company&algorithm=SHA256&digits=8&counter=123', "$uriBuilder");
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