<?php

namespace Vectorface\OtpAuth;

class Base32
{
    const CHARS = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
        'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
        '=' // 32, padding character
    ];

    /**
     * Encode a binary string as base32 (RFC 4648), padded to a multiple of 8 characters.
     */
    public static function encode(string $data): string
    {
        if ($data === '') {
            return '';
        }

        $ret = "";
        $carry = 0;
        $bits = 0;
        foreach (str_split($data) as $c) {
            $carry = ($carry << 8) | ord($c);
            $bits += 8;
            while ($bits >= 5) {
                $ret .= self::CHARS[($carry >> ($bits - 5)) & 31];
                $bits -= 5;
                $carry &= (1 << $bits) - 1;
            }
        }

        if ($bits > 0) {
            $ret .= self::CHARS[($carry << (5 - $bits)) & 31];
        }

        // Pad to a multiple of 8 characters, per RFC 4648.
        if ($pad = (8 - strlen($ret) % 8) % 8) {
            $ret .= str_repeat(self::CHARS[32], $pad);
        }

        return $ret;
    }

    /**
     * Decode a base32 (RFC 4648) string. Padding is optional. Returns null if the
     * input contains any character outside the base32 alphabet.
     */
    public static function decode(string $data): ?string
    {
        if (empty($data)) {
            return null;
        }

        $map = array_flip(self::CHARS);

        $ret = "";
        $carry = 0;
        $bits = 0;
        foreach (str_split($data) as $c) {
            if ($c === self::CHARS[32]) {
                continue;
            }
            if (!isset($map[$c])) {
                return null;
            }
            $carry = ($carry << 5) | $map[$c];
            $bits += 5;

            if ($bits >= 8) {
                $ret .= chr(($carry >> ($bits - 8)) & 0xff);
                $bits -= 8;
                $carry &= (1 << $bits) - 1;
            }
        }

        return $ret;
    }
}
