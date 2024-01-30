<?php

namespace Vectorface\OtpAuth\Paramters;

enum Type: string
{
    case TOTP = 'totp';
    case HOTP = 'hotp';
}
