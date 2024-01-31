<?php

namespace Vectorface\OtpAuth;

use Endroid\QrCode\Builder\Builder;
use Endroid\QrCode\Writer\PngWriter;
use Vectorface\OtpAuth\Paramters\Algorithm;
use Vectorface\OtpAuth\Paramters\Type;

/**
 * A TOTP/HOTP URI builder
 *
 * URIs should be in the format:
 * otpauth://TYPE/LABEL?PARAMETERS
 *
 * Where:
 *  - TYPE is one of "totp" (default) or "hotp"
 *  - LABEL is the account or issue: account (encoded according to rfc3986)
 *  - PARAMETERS are a set of encoded parameters that may/must include:
 *      - secret: A base32-encoded secret (rfc3548)
 *      - issuer: The provider or service with which the account is associated
 *      - algorithm: One of sha1 (default), sha256, or sha512
 *      - digits: Either 6 or 8
 */
class UriBuilder
{
    const SCHEME = "otpauth";
    const DIGITS = [6, 8];

    private string $secret;
    private string $account = '';
    private ?string $issuer = null;
    private Type $type = Type::TOTP;
    private ?Algorithm $algorithm = null;
    private ?int $digits = null;
    private ?int $counter = null;
    private ?int $period = null;

    /**
     * @param string $secret
     * @param bool $encode If true, also base32 encode the secret
     * @return $this
     */
    public function secret(string $secret, bool $encode = false): self
    {
        $this->secret = $encode ? Base32::encode($secret) : $secret;
        return $this;
    }

    public function account(string $account): self
    {
        $this->account = $account;
        return $this;
    }

    public function issuer(string $issuer): self
    {
        $this->issuer = $issuer;
        return $this;
    }

    public function type(Type $type): self
    {
        $this->type = $type;
        return $this;
    }

    public function algorithm(Algorithm $algorithm): self
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    public function digits(int $digits): self
    {
        if (!in_array($digits, self::DIGITS)) {
            throw new \InvalidArgumentException("Number of digits must be 6 or 8");
        }
        $this->digits = $digits;
        return $this;
    }

    public function counter(int $counter): self
    {
        if ($counter < 0) {
            throw new \InvalidArgumentException("Counter must be an integer greater than or equal to zero");
        }
        $this->counter = $counter;
        return $this;
    }

    public function period(int $period): self
    {
        if ($period < 1) {
            throw new \InvalidArgumentException("Period must be an integer greater than zero");
        }
        $this->period = $period;
        return $this;
    }

    public function getUri(): string
    {
        if (!isset($this->secret)) {
            throw new \DomainException("Secret is required for OTP URIs");
        }

        if ($this->type === Type::HOTP && !isset($this->counter)) {
            throw new \DomainException("Counter is a required HOTP parameter");
        }

        if ($this->type === Type::TOTP && isset($this->counter)) {
            throw new \DomainException("Counter parameter does not apply to TOTP");
        }

        if ($this->type === Type::HOTP && isset($this->period)) {
            throw new \DomainException("Period parameter does not apply to HOTP");
        }

        $params = array_filter([
            'secret'    => $this->secret,
            'issuer'    => empty($this->issuer) ? $this->issuer : rawurlencode($this->issuer),
            'algorithm' => $this->algorithm?->value,
            'digits'    => $this->digits,
            'counter'   => $this->counter,
            'period'    => $this->period,
        ]);

        return sprintf(
            "%s://%s/%s?%s",
            self::SCHEME,
            $this->type->value,
            (empty($this->issuer) ? "" : (rawurlencode($this->issuer) . ":%20")) . rawurlencode($this->account),
            implode('&', array_map(fn($k, $v) => "$k=$v", array_keys($params), array_values($params)))
        );
    }

    public function __toString(): string
    {
        return $this->getUri();
    }

    public function getQRCodeDataUri(): string
    {
        return Builder::create()
            ->data($this->getUri())
            ->writer(new PngWriter)
            ->size(260)
            ->margin(10)
            ->build()
            ->getDataUri();
    }
}