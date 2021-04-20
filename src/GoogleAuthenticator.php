<?php

namespace Vectorface;

use Endroid\QrCode\Builder\Builder;
use Endroid\QrCode\Writer\PngWriter;
use Exception;

/**
 * PHP Class for handling Google Authenticator 2-factor authentication
 *
 * @author Michael Kliewe
 * @copyright 2012 Michael Kliewe
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 * @link http://www.phpgangsta.de/
 * @link https://github.com/PHPGangsta/GoogleAuthenticator
 */
class GoogleAuthenticator
{
    protected $_codeLength = 6;

    /**
     * Create new secret.
     * 16 characters, randomly chosen from the allowed base32 characters.
     *
     * @param int $secretLength
     * @return string
     * @throws Exception
     */
    public function createSecret(int $secretLength = 16) : string
    {
        $validChars = self::base32LookupTable();

        // Valid secret lengths are 80 to 640 bits
        if ($secretLength < 16 || $secretLength > 128) {
            throw new Exception('Bad secret length');
        }

        // @codeCoverageIgnoreStart
        $rnd = false;
        if (function_exists('random_bytes')) {
            $rnd = random_bytes($secretLength);
        }

        if (!$rnd) {
            throw new Exception('No source of secure random');
        }
        // @codeCoverageIgnoreEnd

        $secret = '';
        for ($i = 0; $i < $secretLength; ++$i) {
            $secret .= $validChars[ord($rnd[$i]) & 31];
        }

        return $secret;
    }

    /**
     * Calculate the code, with given secret and point in time
     *
     * @param string $secret
     * @param int|null $timeSlice
     * @return string
     * @throws Exception
     */
    public function getCode(string $secret, int $timeSlice = null) : string
    {
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }

        $secretkey = self::base32Decode($secret);
        if (empty($secretkey)) {
            throw new Exception('Could not decode secret');
        }

        // Pack time into binary string
        $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);
        // Hash it with users secret key
        $hm = hash_hmac('SHA1', $time, $secretkey, true);
        // Use last nipple of result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashpart = substr($hm, $offset, 4);

        // Unpak binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        $modulo = pow(10, $this->_codeLength);

        return str_pad($value % $modulo, $this->_codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Get QR-Code URL for image, from our native QRCode API
     *
     * @param string $name
     * @param string $secret
     * @return string
     * @throws Exception on encoding error
     */
    public function getQRCodeUrl(string $name, string $secret) : string
    {
        $uri = "otpauth://totp/$name?secret=$secret";
        return $this->getQRCodeDataUri($uri);
    }

    /**
     * Generate a QRCode for a given string
     *
     * @param string $uri to encode into a QRCode
     * @return string binary data of the PNG of the QRCode
     * @throws Exception
     */
    protected function getQRCodeDataUri(string $uri) : string
    {
        return Builder::create()
            ->data($uri)
            ->writer(new PngWriter)
            ->size(260)
            ->margin(10)
            ->build()
            ->getDataUri();
    }

    /**
     * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
     *
     * @param string $secret
     * @param string $code
     * @param int $discrepancy This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
     * @return bool
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1) : bool
    {
        $currentTimeSlice = floor(time() / 30);

        if (strlen($code) != 6) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            try {
                $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            } catch (Exception $e) {
                return false;
            }

            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Set the code length, should be >=6
     *
     * @param int $length
     * @return self
     */
    public function setCodeLength(int $length) : self
    {
        $this->_codeLength = $length;
        return $this;
    }

    /**
     * Helper class to decode base32
     *
     * @param string $secret
     * @return string
     */
    private static function base32Decode(string $secret) : string
    {
        if (empty($secret)) {
            return '';
        }

        $base32chars = self::base32LookupTable();
        $base32charsFlipped = array_flip($base32chars);

        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = [6, 4, 3, 1, 0];
        if (!in_array($paddingCharCount, $allowedValues)) {
            return '';
        }

        for ($i = 0; $i < 4; $i++){
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])) {
                return '';
            }
        }

        $secret = str_replace('=','', $secret);
        $secret = str_split($secret);
        $binaryString = "";
        for ($i = 0; $i < count($secret); $i = $i+8) {
            if (!in_array($secret[$i], $base32chars)) {
                return '';
            }

            $x = "";
            for ($j = 0; $j < 8; $j++) {
                $secretChar = $secret[$i + $j] ?? 0;
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

    /**
     * Get array with all 32 characters for decoding from/encoding to base32
     *
     * @return array
     */
    private static function base32LookupTable() : array
    {
        return [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '='  // padding char
        ];
    }
}

