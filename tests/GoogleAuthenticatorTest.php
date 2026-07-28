<?php

namespace Tests\Vectorface;

use Exception;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Vectorface\GoogleAuthenticator;
use Vectorface\OtpAuth\Parameters\Algorithm;

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
        // Secret, timeSlice, code, passes
        return [
            // RFC 6238 Appendix B SHA-1 reference vectors. Secret is base32("12345678901234567890");
            // the published codes are 8 digits, so the default 6-digit code is their last 6 digits.
            'RFC6238 T=1'        => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1, '287082', true],
            'RFC6238 T=37037036' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 37037036, '081804', true],
            'RFC6238 T=37037037' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 37037037, '050471', true],
            'RFC6238 T=41152263' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 41152263, '005924', true],
            'RFC6238 T=66666666' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 66666666, '279037', true],
            'RFC6238 wrong code' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1, '000000', false],

            // A 16-character secret (the default createSecret() length).
            'short secret @0'    => ['JBSWY3DPEHPK3PXP', 0, '282760', true],
            'short secret @1'    => ['JBSWY3DPEHPK3PXP', 1, '996554', true],
            'short secret @1e6'  => ['JBSWY3DPEHPK3PXP', 1000000, '041374', true],

            // Original SECRET vectors, corrected to RFC-compliant values (6 chars decodes to 3 bytes).
            'SECRET @0'          => ['SECRET', 0, '857148', true],
            'SECRET @1385909245' => ['SECRET', 1385909245, '979377', true],
            'SECRET @1378934578' => ['SECRET', 1378934578, '560773', true],
            'SECRET wrong code'  => ['SECRET', 1378934578, '000000', false],
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

    /**
     * @throws Exception
     */
    public function testVerifyCodeWithEightDigits()
    {
        $secret = 'SECRET';
        $ga = $this->googleAuthenticator->setCodeLength(8);

        $code = $ga->getCode($secret);
        $this->assertEquals(8, strlen($code));
        $this->assertTrue($ga->verifyCode($secret, $code));

        // A 6-digit code must not verify when 8 digits are configured
        $this->assertFalse($ga->verifyCode($secret, substr($code, 0, 6)));
    }

    /**
     * @throws Exception
     */
    public function testVerifyCodeRejectsNonNumericCode()
    {
        $secret = 'SECRET';

        $this->assertFalse($this->googleAuthenticator->verifyCode($secret, 'abcdef'));
        $this->assertFalse($this->googleAuthenticator->verifyCode($secret, '12345x'));
        $this->assertFalse($this->googleAuthenticator->verifyCode($secret, "12345\n"));
    }

    public function invalidDiscrepancyProvider()
    {
        return [
            'Negative' => [-1],
            'Too large' => [61],
        ];
    }

    /**
     * @dataProvider invalidDiscrepancyProvider
     * @param int $discrepancy
     * @throws Exception
     */
    public function testVerifyCodeRejectsOutOfRangeDiscrepancy(int $discrepancy)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Discrepancy must be between 0 and 60 time slices');

        $this->googleAuthenticator->verifyCode('SECRET', '123456', $discrepancy);
    }

    public function testSetCodeLength()
    {
        $result = $this->googleAuthenticator->setCodeLength(6);

        $this->assertInstanceOf(GoogleAuthenticator::class, $result);
    }

    public function invalidCodeLengthProvider()
    {
        return [
            'Too short' => [5],
            'Too long' => [9],
            'Zero' => [0],
            'Negative' => [-1],
        ];
    }

    /**
     * @dataProvider invalidCodeLengthProvider
     * @param int $length
     */
    public function testSetCodeLengthRejectsOutOfRangeValues(int $length)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Code length must be between 6 and 8');

        $this->googleAuthenticator->setCodeLength($length);
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
