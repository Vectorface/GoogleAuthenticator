<?php

namespace Tests\Vectorface\OtpAuth;

use PHPUnit\Framework\TestCase;
use Vectorface\OtpAuth\Base32;

class Base32Test extends TestCase
{
    /**
     * RFC 4648 base32 test vectors, plus the bug-report example.
     */
    public function katProvider(): array
    {
        return [
            // decoded            => encoded (padded)
            ['', ''],
            ['f', 'MY======'],
            ['fo', 'MZXQ===='],
            ['foo', 'MZXW6==='],
            ['foob', 'MZXW6YQ='],
            ['fooba', 'MZXW6YTB'],
            ['foobar', 'MZXW6YTBOI======'],
            ['Hello, world!', 'JBSWY3DPFQQHO33SNRSCC==='],
        ];
    }

    /**
     * @dataProvider katProvider
     */
    public function testEncodeMatchesKnownAnswers(string $decoded, string $encoded): void
    {
        $this->assertEquals($encoded, Base32::encode($decoded));
    }

    /**
     * @dataProvider katProvider
     */
    public function testDecodeMatchesKnownAnswers(string $decoded, string $encoded): void
    {
        // decode() returns null on empty input.
        $expected = $decoded === '' ? null : $decoded;
        $this->assertEquals($expected, Base32::decode($encoded));
    }

    /**
     * Padding is optional on decode.
     */
    public function testDecodeAcceptsUnpaddedInput(): void
    {
        $this->assertEquals('Hello, world!', Base32::decode('JBSWY3DPFQQHO33SNRSCC'));
    }

    /**
     * Strings containing characters outside the base32 alphabet must be rejected,
     * not silently coerced. This is the bug being fixed: every character is now
     * validated, not just every 8th one.
     */
    public function badInputProvider(): array
    {
        return [
            'bug report example'        => ['L3uj0anUE3lN6JVTRDTKcNqpDsL1RoiuCRXnyQ'],
            'lowercase'                 => ['mzxw6ytb'],
            'digit 0 (not in alphabet)' => ['MZXW6YT0'],
            'digit 1 (not in alphabet)' => ['MZXW6YT1'],
            'digit 8 (not in alphabet)' => ['MZXW6YT8'],
            'invalid in last group'     => ['JBSWY3DPFQQHO33SNRSC!'],
        ];
    }

    /**
     * @dataProvider badInputProvider
     */
    public function testDecodeRejectsInvalidCharacters(string $input): void
    {
        $this->assertNull(Base32::decode($input));
    }

    public function testDecodeRejectsEmptyString(): void
    {
        $this->assertNull(Base32::decode(''));
    }

    /**
     * encode() then decode() must reproduce the original bytes for arbitrary binary input.
     */
    public function testRoundTripForBinaryData(): void
    {
        for ($length = 1; $length <= 64; $length++) {
            $bytes = random_bytes($length);
            $this->assertSame(
                $bytes,
                Base32::decode(Base32::encode($bytes)),
                "round-trip failed for $length bytes"
            );
        }
    }
}
