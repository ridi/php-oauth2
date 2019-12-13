<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Validator;

use Firebase\JWT\JWT;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtSignatureException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Key\KeyHandler;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Checker;
use InvalidArgumentException;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\MissingMandatoryHeaderParameterException;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Jose\Component\Core\JWK;
class JwtTokenValidator
{
    /** @var array */
    private $keys = [];

    /** @var array */
    private $algorithm = [];

    /** @var int */
    private $expire_term = 60 * 5;

    /**
     * @return JwtTokenValidator
     */
    static public function create()
    {
        return new JwtTokenValidator();
    }

    protected function __construct()
    {
    }

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
        if ($function === 'openssl') {
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
     * @return $this
     * @throws AuthorizationException
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

    private function getJws(string $access_token): JWS
    {
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);


        try {
            return $serializerManager->unserialize($access_token);
        } catch (InvalidArgumentException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

    }

    private function checkAndGetHeader(JWS $jws): array
    {
        $headerCheckerManager = new HeaderCheckerManager(
            [
                new AlgorithmChecker(['RS256']), // We check the header "alg" (algorithm)
            ],
            [
                new JWSTokenSupport(), // Adds JWS token type support
            ]
        );
        try {
            $headerCheckerManager->check($jws, 0, ['alg', 'typ', 'kid']);
        } catch (MissingMandatoryHeaderParameterException $e){
            throw new InvalidJwtException($e->getMessage());
        }

        return $jws->getSignature(0)->getProtectedHeader();
    }

    private function checkAndGetClaims(JWS $jws): array
    {
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new Checker\ExpirationTimeChecker(),
            ]
        );
        $claims = json_decode($jws->getPayload(), true);
        try {
            $claimCheckerManager->check($claims, ['sub', 'u_idx', 'exp', 'client_id']);
        } catch (InvalidClaimException $e) {
            throw new InvalidJwtException($e->getMessage());
        } catch (MissingMandatoryClaimException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        return $claims;
    }

    private function verifyJwsWithJwk(JWS $jws, JWK $jwk): void
    {
        $algorithmManager = new AlgorithmManager([
            new RS256(),
        ]);
        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );

        try {
            $isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);
        } catch (InvalidArgumentException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        if (!$isVerified) {
            throw new InvalidJwtSignatureException();
        }
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

        $jws = $this->getJws($access_token);
        $header = $this->checkAndGetHeader($jws);
        $claims = $this->checkAndGetClaims($jws);

        // TODO : 아래 주석 처리하기
//        if (empty($this->keys[$header->alg])) {
//            throw new InvalidJwtException("No matched algorithm in registered keys");
//        }

        $jwk = KeyHandler::get_public_key_by_kid($claims['client_id'], $header['kid']);
        $this->verifyJwsWithJwk($jws, $jwk);

        return JwtToken::createFrom($claims);
    }
}
