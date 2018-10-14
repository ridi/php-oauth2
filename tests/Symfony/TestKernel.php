<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Symfony;

use Ridibooks\OAuth2\Symfony\OAuth2ServiceProviderBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\RouteCollectionBuilder;

class TestKernel extends Kernel
{
    use MicroKernelTrait;

    public function registerBundles()
    {
        return [
            new FrameworkBundle(),
            new OAuth2ServiceProviderBundle()
        ];
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader)
    {
        $config_dir = self::getConfigDir();
        $loader->load($config_dir . '/{packages}/*.yml', 'glob');
        $loader->load($config_dir . '/{services}.yml', 'glob');
    }

    protected function configureRoutes(RouteCollectionBuilder $routes)
    {
        $routes->import(TestController::class, '/', 'annotation');
    }

    /**
     * @return string
     */
    private static function getConfigDir(): string
    {
        return __DIR__ . '/config';
    }
}
