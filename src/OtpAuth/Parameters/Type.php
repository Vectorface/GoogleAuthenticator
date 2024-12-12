<?php

namespace Vectorface\OtpAuth\Parameters;

enum Type: string
{
    case TOTP = 'totp';
    case HOTP = 'hotp';
}
