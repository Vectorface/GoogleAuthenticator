<?php

namespace Vectorface\OtpAuth\Parameters;

enum Algorithm: string
{
    case SHA1 = 'SHA1';
    case SHA256 = 'SHA256';
    case SHA512 = 'SHA512';
}
