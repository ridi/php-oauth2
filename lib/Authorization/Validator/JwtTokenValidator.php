<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Validator;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredConstantException;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtSignatureException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidTokenException;
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
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\MissingMandatoryHeaderParameterException;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Jose\Component\Core\JWK;
use InvalidArgumentException;

class JwtTokenValidator
{
    /** @var JwkHandler */
    private $jwkHandler;

    /** @var JWSSerializerManager */
    private $serializerManager;

    /** @var HeaderCheckerManager */
    private $headerCheckerManager;

    /** @var ClaimCheckerManager */
    private $claimCheckerManager;

    /** @var AlgorithmManager */
    private $algorithmManager;

    /** @var JWSVerifier */
    private $jwsVerifier;


    /**
     * @return JwtTokenValidator
     */
    static public function createWithJWKHandler(JwkHandler $jwk_handler): JwtTokenValidator
    {
        return new JwtTokenValidator($jwk_handler);
    }

    protected function __construct(JwkHandler $jwk_handler)
    {
        $this->jwkHandler = $jwk_handler;
        $this->serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        $this->headerCheckerManager = new HeaderCheckerManager(
            [
                new AlgorithmChecker(['RS256', 'ES256']),
            ],
            [
                new JWSTokenSupport(),
            ]
        );
        $this->claimCheckerManager = new ClaimCheckerManager(
            [
                new Checker\ExpirationTimeChecker(),
            ]
        );
        $this->algorithmManager = new AlgorithmManager([
            new RS256(),
            new ES256(),
        ]);
        $this->jwsVerifier = new JWSVerifier(
            $this->algorithmManager
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
            return $this->serializerManager->unserialize($access_token);
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
            $this->headerCheckerManager->check($jws, 0, ['alg', 'typ', 'kid']);
        } catch (MissingMandatoryHeaderParameterException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        return $jws->getSignature(0)->getProtectedHeader();
    }

    # TODO : InvalidTokenException 랑 InvalidJwtException 차이 알아보자
    /**
     * @param JWS $jws
     * @return array
     * @throws ExpiredTokenException
     * @throws InvalidTokenException
     */
    private function checkAndGetClaims(JWS $jws): array
    {
        $claims = json_decode($jws->getPayload(), true);
        try {
            $this->claimCheckerManager->check($claims, ['sub', 'u_idx', 'exp', 'client_id']);
        } catch (InvalidClaimException $e) {
            throw new ExpiredTokenException($e->getMessage());
        } catch (MissingMandatoryClaimException $e) {
            throw new InvalidTokenException($e->getMessage());
        }

        return $claims;
    }

    /**
     * @param JWS $jws
     * @param JWK $JWK
     * @return void
     * @throws InvalidJwtException
     * @throws InvalidJwtSignatureException
     */
    private function verifyJwsWithJwk(JWS $jws, JWK $jwk): void
    {
        try {
            $isVerified = $this->jwsVerifier->verifyWithKey($jws, $jwk, 0);
        } catch (InvalidArgumentException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        if (!$isVerified) {
            throw new InvalidJwtSignatureException();
        }
    }

    /**
     * @param int $expiration_sec
     * @return $this
     * @throws ExpiredConstantException
     */
    public function setKeyHandlerExpirationMin(int $expiration_sec)
    {
        $this->jwkHandler->setExperationSec($expiration_sec);

        return $this;
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

        $jwk = $this->jwkHandler->getPublicKeyByKid($claims['client_id'], $header['kid']);
        $this->verifyJwsWithJwk($jws, $jwk);

        return JwtToken::createFrom($claims);
    }
}
