<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2\Symfony\DependencyInjection;

use Ridibooks\OAuth2\Symfony\Provider\DefaultUserProvider;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    /**
     * @return TreeBuilder
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $tree_builder = new TreeBuilder();
        $root_node = $tree_builder->root('o_auth2_service_provider');

        $root_node
            ->children()
                ->scalarNode('client_id')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('client_secret')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('client_default_scope')
                    ->defaultValue([])
                ->end()
                ->scalarNode('client_default_redirect_uri')
                    ->defaultNull()
                ->end()
                ->scalarNode('authorize_url')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('token_url')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('key_url')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('user_info_url')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('token_cookie_domain')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->integerNode('jwt_expiration_min')
                    ->defaultValue(5 * 60)
                ->end()
                ->scalarNode('default_user_provider')
                    ->cannotBeEmpty()
                    ->defaultValue(DefaultUserProvider::class)
                ->end()
                ->scalarNode('default_exception_handler')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
            ->end();

        return $tree_builder;
    }
}
