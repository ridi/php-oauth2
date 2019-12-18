<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Validator;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtSignatureException;
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
    /** @var string */
    private $jwk_url;

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
     * @return JwtTokenValidator
     */
    static public function createWithJwkUrl(string $jwk_url): JwtTokenValidator
    {
        return new JwtTokenValidator($jwk_url);
    }

    protected function __construct(string $jwk_url)
    {
        $this->jwk_url = $jwk_url;
        $this->serializer_manager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        $this->header_checker_manager = new HeaderCheckerManager(
            [
                new AlgorithmChecker(['RS256', 'ES256']),
            ],
            [
                new JWSTokenSupport(),
            ]
        );
        $this->claim_checker_manager = new ClaimCheckerManager(
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
            $this->header_checker_manager->check($jws, 0, ['alg', 'typ', 'kid']);
        } catch (MissingMandatoryHeaderParameterException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        return $jws->getSignature(0)->getProtectedHeader();
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
        } catch (InvalidClaimException $e) {
            throw new ExpiredTokenException($e->getMessage());
        } catch (MissingMandatoryClaimException $e) {
            throw new InvalidJwtException($e->getMessage());
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
            $isVerified = $this->jws_verifier->verifyWithKey($jws, $jwk, 0);
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

        $jwk = JwkHandler::getPublicKeyByKid($this->jwk_url, $claims['client_id'], $header['kid']);
        $this->verifyJwsWithJwk($jws, $jwk);

        return JwtToken::createFrom($claims);
    }
}
