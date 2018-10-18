<?php

require __DIR__ . '/../../lib/Symfony/vendor/autoload.php';

$source_path = __DIR__ . '/../../lib/Symfony';
$aspect_mock_kernel = \AspectMock\Kernel::getInstance();
$aspect_mock_kernel->init([
    'cacheDir' => join(DIRECTORY_SEPARATOR, [__DIR__, 'aspect_mock']),
    'debug' => true,
    'includePaths' => [$source_path],
    'excludePaths' => ["{$source_path}/vendor"]
]);
