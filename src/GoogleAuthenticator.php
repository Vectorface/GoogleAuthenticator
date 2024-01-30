<?php

namespace Vectorface;

use Endroid\QrCode\Builder\Builder;
use Endroid\QrCode\Writer\PngWriter;
use Exception;
use Vectorface\OtpAuth\Base32;
use Vectorface\OtpAuth\UriBuilder;

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

        return Base32::encode($rnd, $secretLength);
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

        $secretkey = Base32::decode($secret);
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
        $uri = $this->getUriBuilder()
            ->account($name)
            ->secret($secret)
            ->getUri();
        return $this->getQRCodeDataUri($uri);
    }

    /**
     * Build an OTP URI using the builder pattern
     *
     * @return UriBuilder
     */
    public function getUriBuilder(): UriBuilder
    {
        $builder = new UriBuilder();
        if ($this->_codeLength !== 6) {
            $builder->digits($this->_codeLength);
        }
        return $builder;
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
}

