<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Authorization\Validator;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;

class JwtTokenValidator
{
    private $jwt_info;

    public function __construct(JwtInfo $jwt_info)
    {
        $this->jwt_info = $jwt_info;
    }

    /**
     * @param string|null $access_token
     * @return JwtToken
     * @throws AuthorizationException
     * @throws TokenNotFoundException
     */
    public function validateToken($access_token): JwtToken
    {
        if (!isset($access_token)) {
            throw new TokenNotFoundException();
        }

        JWT::$leeway = $this->jwt_info->getExpireTerm();
        try {
            $token = JWT::decode($access_token, $this->jwt_info->getSecret(), [$this->jwt_info->getAlgorithm()]);
            return JwtToken::createFrom($token);
        } catch (SignatureInvalidException $e) {
            throw new InvalidJwtException($e);
        } catch (ExpiredException $e) {
            throw new ExpiredTokenException();
        } catch (\UnexpectedValueException $e) {
            throw new InvalidJwtException($e);
        }
    }
}
