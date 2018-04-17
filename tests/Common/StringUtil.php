<?php
namespace Ridibooks\Test\OAuth2\Common;

class StringUtil
{
    const RANDOM_STRING = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+{}[]';

    public static function getRandomString(int $length): string
    {
        return substr(
            str_shuffle(self::RANDOM_STRING),
            0,
            $length
        );
    }
}
