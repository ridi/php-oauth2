<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Authorization\Validator;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtSignatureException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;

class JwtTokenValidator
{
    /** @var array */
    private $keys = [];

    /** @var array  */
    private $algorithm = [];

    /** @var int  */
    private $expire_term = 60 * 5;

    /**
     * @return JwtTokenValidator
     */
    static public function create() {
        return new JwtTokenValidator();
    }

    protected function __construct() {}

    /**\=
     * @param string $path
     * @return string
     * @throws AuthorizationException
     */
    private function readKeyFile(string $path, string $algorithm)
    {
        $key = file_get_contents($path);
        if ($key === false) {
            throw new AuthorizationException("Not found key file from ${path}");
        }

        list($function) = JWT::$supported_algs[$algorithm];
        if($function === 'openssl') {
            $key = openssl_pkey_get_public($key);

            if ($key === false) {
                throw new AuthorizationException("Not found key file from ${path}");
            }
        }

        return $key;
    }

    private function addAlgorithm($algorithm)
    {
        if (!in_array($algorithm, $this->algorithm) && in_array($algorithm, array_keys(JWT::$supported_algs))) {
            $this->algorithm[] = $algorithm;
        }
    }

    /**
     * @param string $key
     * @param string $algorithm
     * @param string $key_id
     * @return $this
     */
    public function addKey(string $key_id, string $key, string $algorithm)
    {
        $this->keys[$algorithm][$key_id] = $key;
        $this->addAlgorithm($algorithm);
        return $this;
    }

    /**
     * @param string $key_id
     * @param string $algorithm
     * @param string $path
     * @throws AuthorizationException
     * @return $this
     */
    public function addKeyFromFile(string $key_id, string $path, string $algorithm)
    {
        $this->keys[$algorithm][$key_id] = $this->readKeyFile($path, $algorithm);
        $this->addAlgorithm($algorithm);
        return $this;
    }

    /**
     * @param $expire_term
     * @return $this
     */
    public function setExpireTerm(int $expire_term)
    {
        if (is_numeric($expire_term)) {
            $this->expire_term = $expire_term;
        }
        return $this;
    }

    private function readJwtHeader($jwt)
    {
        $tks = explode('.', $jwt);
        if (count($tks) != 3) {
            throw new InvalidJwtException('Wrong number of segments');
        }
        list($headb64) = $tks;
        if (null === ($header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64)))) {
            throw new InvalidJwtException('Invalid header encoding');
        }
        return $header;
    }

    /**
     * @param string|null $access_token
     * @return JwtToken
     * @throws AuthorizationException
     * @throws TokenNotFoundException
     */
    public function validateToken($access_token): JwtToken
    {
        JWT::$leeway = $this->expire_term;

        if (!isset($access_token)) {
            throw new TokenNotFoundException();
        }

        $header = $this->readJwtHeader($access_token);

        if (!isset($header->alg)) {
            throw new InvalidJwtException('Empty algorithm');
        }

        if (empty($this->keys[$header->alg])) {
            throw new InvalidJwtException("No matched algorithm in registered keys");
        }

        $key_iterate = [];
        if (empty($header->kid)) {
            $key_iterate = array_values($this->keys[$header->alg]);
        } else {
            $key_iterate[] = $this->keys[$header->alg];
        }

        $verified = false;
        $token = null;
        foreach ($key_iterate as $key) {
            try {
                $token = JWT::decode($access_token, $key, $this->algorithm);
                $verified = true;
            } catch (\DomainException $e) {
                continue;
            } catch (SignatureInvalidException $e) {
                continue;
            } catch (ExpiredException $e) {
                throw new ExpiredTokenException();
            } catch (\UnexpectedValueException $e) {
                throw new InvalidJwtException($e->getMessage());
            }
        }

        if (!$verified) {
            throw new InvalidJwtSignatureException();
        }

        return JwtToken::createFrom($token);
    }
}
