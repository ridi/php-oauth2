<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Validator;

use Psr\Cache\CacheException;
use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtSignatureException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\NotExistedKeyException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Jwk\JwkHandler;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWS;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Checker;
use InvalidArgumentException;
use Psr\Cache\CacheItemPoolInterface;

const SIGNATURE_INDEX = 0;

class JwtTokenValidator
{
    /** @var JwkHandler */
    private $jwk_handler;

    /** @var JWSSerializerManager */
    private $serializer_manager;

    /** @var HeaderCheckerManager */
    private $header_checker_manager;

    /** @var ClaimCheckerManager */
    private $claim_checker_manager;

    /** @var AlgorithmManager */
    private $algorithm_manager;

    /** @var JWSVerifier */
    private $jws_verifier;

    /**
     * @param string $jwk_url
     * @param CacheItemPoolInterface|null $cache_item_pool
     * @return void
     */
    public function __construct(string $jwk_url, ?CacheItemPoolInterface $cache_item_pool = null)
    {
        $this->jwk_handler = new JwkHandler($jwk_url, $cache_item_pool);
        $this->serializer_manager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        $this->header_checker_manager = new Checker\HeaderCheckerManager(
            [
                new Checker\AlgorithmChecker(['RS256', 'ES256']),
            ],
            [
                new JWSTokenSupport(),
            ]
        );
        $this->claim_checker_manager = new Checker\ClaimCheckerManager(
            [
                new Checker\ExpirationTimeChecker(),
            ]
        );
        $this->algorithm_manager = new AlgorithmManager([
            new RS256(),
            new ES256(),
        ]);
        $this->jws_verifier = new JWSVerifier(
            $this->algorithm_manager
        );
    }

    /**
     * @param string $access_token
     * @return JWS
     * @throws InvalidJwtException
     */
    private function getJws(string $access_token): JWS
    {
        try {
            return $this->serializer_manager->unserialize($access_token);
        } catch (InvalidArgumentException $e) {
            throw new InvalidJwtException($e->getMessage());
        }
    }

    /**
     * @param JWS $jws
     * @return array
     * @throws InvalidJwtException
     */
    private function checkAndGetHeader(JWS $jws): array
    {
        try {
            $this->header_checker_manager->check($jws, SIGNATURE_INDEX, ['alg', 'typ', 'kid']);
        } catch (Checker\MissingMandatoryHeaderParameterException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        return $jws->getSignature(SIGNATURE_INDEX)->getProtectedHeader();
    }

    /**
     * @param JWS $jws
     * @return array
     * @throws ExpiredTokenException
     * @throws InvalidJwtException
     */
    private function checkAndGetClaims(JWS $jws): array
    {
        $claims = json_decode($jws->getPayload(), true);
        try {
            $this->claim_checker_manager->check($claims, ['sub', 'u_idx', 'exp', 'client_id']);
        } catch (Checker\InvalidClaimException $e) {
            throw new ExpiredTokenException($e->getMessage());
        } catch (Checker\MissingMandatoryClaimException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        return $claims;
    }

    /**
     * @param JWS $jws
     * @param JWK $jwk
     * @return void
     * @throws InvalidJwtException
     * @throws InvalidJwtSignatureException
     */
    private function verifyJwsWithJwk(JWS $jws, JWK $jwk): void
    {
        try {
            $isVerified = $this->jws_verifier->verifyWithKey($jws, $jwk, SIGNATURE_INDEX);
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
     * @throws InvalidJwtException
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     * @throws AccountServerException
     * @throws ClientRequestException
     * @throws CacheException
     */
    public function validateToken($access_token): JwtToken
    {
        if (!isset($access_token)) {
            throw new TokenNotFoundException();
        }

        $jws = $this->getJws($access_token);

        $header = $this->checkAndGetHeader($jws);
        $claims = $this->checkAndGetClaims($jws);

        $jwk = $this->jwk_handler->getJwk($claims['client_id'], $header['kid']);
        $this->verifyJwsWithJwk($jws, $jwk);

        return JwtToken::createFrom($claims);
    }
}
