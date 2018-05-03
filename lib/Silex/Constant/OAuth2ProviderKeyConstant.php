<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Constant;

class OAuth2ProviderKeyConstant
{
    // Configurations
    const CLIENT_ID = 'ridi.oauth2.client_id';
    const CLIENT_SECRET = 'ridi.oauth2.client_secret';
    const CLIENT_DEFAULT_SCOPE = 'ridi.oauth2.default_scope';
    const CLIENT_DEFAULT_REDIRECT_URI = 'ridi.oauth2.default_redirect_uri';

    const AUTHORIZE_URL = 'ridi.oauth2.authorize_url';
    const TOKEN_URL = 'ridi.oauth2.token_url';
    const USER_INFO_URL = 'ridi.oauth2.user_info_url';

    const JWT_ALGORITHM = 'ridi.oauth2.jwt_algorithm';
    const JWT_SECRET = 'ridi.oauth2.jwt_secret';
    const JWT_EXPIRE_TERM = 'ridi.oauth2.jwt_expire_term';

    const DEFAULT_EXCEPTION_HANDLER = 'ridi.oauth2.default_exception_handler';
    const DEFAULT_USER_PROVIDER = 'ridi.oauth2.default_user_provider';

    // Services
    const GRANTER = 'ridi.oauth2.granter';
    const AUTHORIZER = 'ridi.oauth2.authorizer';
    const MIDDLEWARE = 'ridi.oauth2.middleware';

    // Returns
    const USER = 'ridi.oauth2.user';
    const STATE = 'ridi.oauth2.state';
}
