<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Authorization\Validator;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtsignatureException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;

class JwtTokenValidator
{
    /** @var array */
    private $keys_without_kid = [];

    /** @var array */
    private $keys_with_kid = [];

    /** @var array  */
    private $algorithm = ['HS256', 'RS256'];

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
            var_dump($key);

            if ($key === false) {
                throw new AuthorizationException("Not found key file from ${path}");
            }
        }

        return $key;
    }

    /**
     * @param string $key
     * @param string $algorithm
     * @param string|null $key_id
     * @return $this
     */
    public function addKey(string $key, string $algorithm, string $key_id = null)
    {
        if (empty($key_id)) {
            $this->keys_without_kid[$algorithm][] = $key;
        } else {
            $this->keys_with_kid[$algorithm][$key_id] = $key;
        }
        return $this;
    }

    /**
     * @param string|null $key_id
     * @param string $algorithm
     * @param string $path
     * @throws AuthorizationException
     * @return $this
     */
    public function addKeyFromFile(string $path, string $algorithm, string $key_id = null)
    {
        if (empty($key_id)) {
            $this->keys_without_kid[$algorithm][] = $this->readKeyFile($path, $algorithm);
        } else {
            $this->keys_with_kid[$algorithm][$key_id] = $this->readKeyFile($path, $algorithm);
        }
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

        $key_iterate = [];
        if (empty($header->kid) && !empty($this->keys_without_kid[$header->alg])) {
            $key_iterate = $this->keys_without_kid[$header->alg];
        } else if (!empty($header->kid) && !empty($this->keys_with_kid[$header->alg])) {
            $key_iterate[] = $this->keys_with_kid[$header->alg];
        }

        if (empty($key_iterate)) {
            throw new InvalidJwtException('No matched validation key');
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
            throw new InvalidJwtsignatureException();
        }

        return JwtToken::createFrom($token);
    }
}
