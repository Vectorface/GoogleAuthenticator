<?php

namespace Tests\Vectorface;

use Vectorface\GoogleAuthenticator;

class GoogleAuthenticatorTest extends \PHPUnit\Framework\TestCase
{
    /* @var GoogleAuthenticator $googleAuthenticator */
    protected $googleAuthenticator;

    protected $qrCodeUrl;

    protected function setUp()
    {
        $this->googleAuthenticator = new GoogleAuthenticator();
        $this->qrCodeUrl = trim(file_get_contents(__DIR__ . '/fixtures/qr-code-url.txt'));
    }

    public function testItCanBeInstantiated()
    {
        $ga = new GoogleAuthenticator();

        $this->assertInstanceOf(GoogleAuthenticator::class, $ga);
    }

    /**
     * @throws \Exception
     */
    public function testCreateSecretDefaultsToSixteenCharacters()
    {
        $ga = $this->googleAuthenticator;
        $secret = $ga->createSecret();

        $this->assertEquals(strlen($secret), 16);
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
     * @throws \Exception
     */
    public function testCreateSecretLengthCanBeSpecified($secretLength)
    {
        $ga = $this->googleAuthenticator;

        if ($secretLength < 16 || $secretLength > 128) {
            $this->expectException(\Exception::class);
            $this->expectExceptionMessage('Bad secret length');
        }

        $secret = $ga->createSecret($secretLength);

        $this->assertEquals(strlen($secret), $secretLength);
    }

    public function codeProvider()
    {
        // Secret, time, code
        return [
            ['SECRET', '0', '200470', true],
            ['SECRET', '1385909245', '780018', true],
            ['SECRET', '1378934578', '705013', true],
            ['SECRET', '1378934578', '000000', false],
        ];
    }

    /**
     * @dataProvider codeProvider
     * @param string $secret
     * @param int|null $timeSlice
     * @param string $code
     * @param bool $passes
     * @throws \Exception
     */
    public function testGetCodeReturnsCorrectValues($secret, $timeSlice, $code, $passes)
    {
        $generatedCode = $this->googleAuthenticator->getCode($secret, $timeSlice);

        if ($passes) {
            $this->assertEquals($code, $generatedCode);
        } else {
            $this->assertNotEquals($code, $generatedCode);
        }
    }

    /**
     * @throws \Exception
     */
    public function testGetQRCodeUrl()
    {
        $secret = 'SECRET';
        $name = 'Test';
        $url = $this->googleAuthenticator->getQRCodeUrl($name, $secret);

        $this->assertEquals($url, $this->qrCodeUrl);
    }

    /**
     * @throws \Exception
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
     * @throws \Exception
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
            [''], // Empty secrets not allowed
            ['n'], // Only allows uppercase letters
            ['=='], // Not correct number of = padding
            ['===A==='], // Padding = should only appear at the end
        ];
    }

    /**
     * @dataProvider badSecretProvider
     * @param string $secret
     * @throws \Exception
     */
    public function testGetCodeWithBadSecret($secret)
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Could not decode secret');

        $code = $this->googleAuthenticator->getCode($secret);
        $this->assertEquals('', $code);
    }
}
