<?php declare(strict_types=1);
namespace Ridibooks\OAuth2Resource\Authorization\Validator;


use Lcobucci\JWT\Parser;
use Ridibooks\OAuth2Resource\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2Resource\Authorization\Token\JwtToken;

class JwtTokenValidator
{
    private $jwt_info;

    public function __construct(JwtInfo $jwt_info)
    {
        $this->jwt_info = $jwt_info;
    }

    /**
     * @param string $access_token
     * @return JwtToken
     * @throws InvalidJwtException
     */
    public function validateToken(string $access_token): JwtToken
    {
        if (empty($access_token)) {
            throw new InvalidJwtException('access_token is empty');
        }

        try {
            $token = (new Parser())->parse($access_token);
            if ($token->verify($this->jwt_info->getSigner(), $this->jwt_info->getSecret()) === false) {
                throw new InvalidJwtException('Access token could not be verified');
            }

            return JwtToken::createFrom($token);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidJwtException($e->getMessage());
        } catch (\RuntimeException $e) {
            throw new InvalidJwtException($e->getMessage());
        }
    }
}
