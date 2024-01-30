<?php

namespace Tests\Vectorface;

use Exception;
use PHPUnit\Framework\TestCase;
use Vectorface\GoogleAuthenticator;
use Vectorface\OtpAuth\Paramters\Algorithm;

class GoogleAuthenticatorTest extends TestCase
{
    /* @var GoogleAuthenticator $googleAuthenticator */
    protected $googleAuthenticator;

    protected function setUp() : void
    {
        $this->googleAuthenticator = new GoogleAuthenticator();
    }

    public function testItCanBeInstantiated()
    {
        $ga = new GoogleAuthenticator();

        $this->assertInstanceOf(GoogleAuthenticator::class, $ga);
    }

    /**
     * @throws Exception
     */
    public function testCreateSecretDefaultsToSixteenCharacters()
    {
        $ga = $this->googleAuthenticator;
        $secret = $ga->createSecret();

        $this->assertEquals(16, strlen($secret));
    }

    public function secretLengthProvider()
    {
        return [
            range(0, 200)
        ];
    }

    /**
     * @dataProvider secretLengthProvider
     * @param int $secretLength
     * @throws Exception
     */
    public function testCreateSecretLengthCanBeSpecified(int $secretLength)
    {
        $ga = $this->googleAuthenticator;

        if ($secretLength < 16 || $secretLength > 128) {
            $this->expectException(Exception::class);
            $this->expectExceptionMessage('Bad secret length');
        }

        $secret = $ga->createSecret($secretLength);

        $this->assertEquals(strlen($secret), $secretLength);
    }

    public function codeProvider()
    {
        // Secret, time, code, passes
        return [
            ['SECRET', 0, '200470', true],
            ['SECRET', 1385909245, '780018', true],
            ['SECRET', 1378934578, '705013', true],
            ['SECRET', 1378934578, '000000', false],
        ];
    }

    /**
     * @dataProvider codeProvider
     * @param string $secret
     * @param int|null $timeSlice
     * @param string $code
     * @param bool $passes
     * @throws Exception
     */
    public function testGetCodeReturnsCorrectValues(string $secret, ?int $timeSlice, string $code, bool $passes)
    {
        $generatedCode = $this->googleAuthenticator->getCode($secret, $timeSlice);

        if ($passes) {
            $this->assertEquals($code, $generatedCode);
        } else {
            $this->assertNotEquals($code, $generatedCode);
        }
    }

    /**
     * @throws Exception
     */
    public function testGetQRCodeUrl()
    {
        $secret = 'SECRET';
        $name = 'Test';
        $url = $this->googleAuthenticator->getQRCodeUrl($name, $secret);

        $prefix = 'data:image/png;base64,';
        $this->assertStringStartsWith($prefix, $url);

        $base64part = substr($url, strlen($prefix));
        $this->assertMatchesRegularExpression("#^[a-zA-Z0-9/+]*={0,2}$#", $base64part);
    }

    /**
     * @throws Exception
     */
    public function testVerifyCode()
    {
        // Good result
        $secret = 'SECRET';
        $code = $this->googleAuthenticator->getCode($secret);
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(true, $result);

        // Wrong length
        $code = 'INVALIDCODE';
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(false, $result);

        // Wrong code
        $code = '123456';
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(false, $result);

        // Bad secret
        $result = $this->googleAuthenticator->verifyCode('', $code);
        $this->assertEquals(false, $result);
    }

    /**
     * @throws Exception
     */
    public function testVerifyCodeWithLeadingZero()
    {
        $secret = 'SECRET';
        $code = $this->googleAuthenticator->getCode($secret);
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(true, $result);

        $code = '0'.$code;
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(false, $result);
    }

    public function testSetCodeLength()
    {
        $result = $this->googleAuthenticator->setCodeLength(6);

        $this->assertInstanceOf(GoogleAuthenticator::class, $result);
    }

    public function badSecretProvider()
    {
        return [
            "Empty secrets not allowed" => [''],
            "Only allows uppercase letters" => ['n'],
            "Not correct number of = padding" => ['=='],
            "Padding = should only appear at the end" => ['===A==='],
        ];
    }

    /**
     * @dataProvider badSecretProvider
     * @param string $secret
     * @throws Exception
     */
    public function testGetCodeWithBadSecret(string $secret)
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Could not decode secret');

        $code = $this->googleAuthenticator->getCode($secret);
        $this->assertEquals('', $code);
    }

    /**
     * Ensure URL builder emits correctly with minimal params
     * @return void
     */
    public function testUriBuilderDefaults()
    {
        $builder = $this->googleAuthenticator->getUriBuilder()
            ->account("foo")
            ->secret("bar");

        $this->assertEquals("otpauth://totp/foo?secret=bar", "$builder");
    }

    /**
     * Ensure URL builder emits all params correctly
     *
     * @return void
     * @throws Exception
     */
    public function testUriBuilderParams()
    {
        $secret = $this->googleAuthenticator->createSecret();
        $digits = 8;
        $period = 60;
        $algorithm = Algorithm::SHA256;
        $builder = $this->googleAuthenticator
            ->setCodeLength(8)
            ->getUriBuilder()
                ->account("foo")
                ->secret($secret)
                ->issuer("bar+baz&quux")
                ->algorithm($algorithm)
                ->period($period);

        $this->assertEquals(
            "otpauth://totp/bar%2Bbaz%26quux:%20foo?secret={$secret}&issuer=bar%2Bbaz%26quux&algorithm={$algorithm->value}&digits={$digits}&period={$period}",
            "$builder"
        );
    }
}
