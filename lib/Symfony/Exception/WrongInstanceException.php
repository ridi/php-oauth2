<?php
namespace Ridibooks\OAuth2Resource\Symfony\Exception;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

class WrongInstanceException extends HttpException
{
    public function __construct()
    {
        parent::__construct(Response::HTTP_INTERNAL_SERVER_ERROR);
    }
}
