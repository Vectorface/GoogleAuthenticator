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
     * Helper method to encode base32
     *
     * @param string $data
     * @param $length
     * @return string
     */
    public static function encode(string $data, $length = null): string
    {
        $length ??= strlen($data);
        $encoded = '';
        for ($i = 0; $i < $length; ++$i) {
            $encoded .= self::CHARS[ord($data[$i]) & 31];
        }
        return $encoded;
    }

    /**
     * Helper method to decode base32
     *
     * @param string $data
     * @return ?string The decoded string, or null on error
     */
    public static function decode(string $data): ?string
    {
        if (empty($data)) {
            return '';
        }

        $base32charsFlipped = array_flip(self::CHARS);
        $paddingCharCount = substr_count($data, self::CHARS[32]);
        $allowedValues = [6, 4, 3, 1, 0];
        if (!in_array($paddingCharCount, $allowedValues)) {
            return null;
        }

        for ($i = 0; $i < 4; $i++){
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($data, -($allowedValues[$i])) != str_repeat(self::CHARS[32], $allowedValues[$i])) {
                return null;
            }
        }

        $data = str_replace('=','', $data);
        $data = str_split($data);
        $binaryString = "";
        for ($i = 0; $i < count($data); $i = $i+8) {
            if (!isset($base32charsFlipped[$data[$i]])) {
                return null;
            }

            $x = "";
            for ($j = 0; $j < 8; $j++) {
                $secretChar = $data[$i + $j] ?? 0;
                $base = $base32charsFlipped[$secretChar] ?? 0;
                $x .= str_pad(base_convert($base, 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            for ($z = 0; $z < count($eightBits); $z++) {
                $binaryString .= ( ($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48 ) ? $y : "";
            }
        }

        return $binaryString;
    }
}