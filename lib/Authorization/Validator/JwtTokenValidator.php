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
    /** @var string  */
    private $secret;

    /** @var string  */
    private $algorithm;

    /** @var int  */
    private $expire_term;

    /**
     * @param string $secret
     * @param string $algorithm
     * @param int $expire_term in second
     */
    public function __construct(string $secret, string $algorithm, int $expire_term)
    {
        $this->secret = $secret;
        $this->algorithm = $algorithm;
        $this->expire_term = $expire_term;
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

        JWT::$leeway = $this->expire_term;
        try {
            $token = JWT::decode($access_token, $this->secret, [$this->algorithm]);
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
