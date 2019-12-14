<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Key;

use GuzzleHttp\Client;
use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;

class KeyRequestor
{
    public static function requestPublicKey(
        string $client_id
    ): array
    {
        # TODO: 리팩토링하자.
//        $oauth2_service_provider->getConfigs()['token_cookie_domain']
        $client = new Client();
        # TODO: 나중에 $client_id 넣자.
        $response = $client->request('GET',
            'https://account.dev.ridi.io/oauth2/keys/public', [
                'query' => ['client_id' => 'Nkt2Xdc0zMuWmye6MSkYgqCh9q6JjeMCsUiH1kgL']
            ]);

        ## TODO: 아래걸로 추후 변경
//        return self::processResponse($response);

        # TODO: $key_araay 나중에 위에걸로 바꾸자.
        $mock_data = <<<EOT
        {"keys":[
        {"kid": "RS999", "alg": "RS256", "kty": "RSA", "use": "sig", "n": "1rL5PCEv2PaAASaGldzfnlo0MiMCglC-eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP_QDk3NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg_FuplBFT82e14UVmZx4kP-HwDjaSpvYHoTr3b5j20Ebx7aIy_SVrWeY0wxeAdFf-EOuEBQ-QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsBLCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAnIQ==", "e": "AQAB"},
        {"kid": "kid1", "alg": "RS256", "kty": "RSA", "use": "sig", "n": "1rL5PCEv2PaAASaGldzfnlo0MiMCglC-eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP_QDk3NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg_FuplBFT82e14UVmZx4kP-HwDjaSpvYHoTr3b5j20Ebx7aIy_SVrWeY0wxeAdFf-EOuEBQ-QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsBLCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAnIQ==", "e": "AQAB"}
        ]}
EOT;

        return json_decode($mock_data, true);
    }

    public static function processResponse(
        Response $response
    )
    {

        if ($response->getStatusCode() >= 500) {
            throw new AccountServerException();
        } else if ($response->getStatusCode() >= 400) {
            throw new ClientRequestException();
        }

        $json_decode = json_decode($response->getBody()->getContents(), true);
        return $json_decode;
    }
}
