<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Cache;

use Ridibooks\OAuth2\Authorization\Exception\CacheFileIOException;

const CACHE_VARIABLE_NAME = 'cache_variable_name';
const DEFAULT_TTL = 600;

class CacheManager
{
    /**
     * @param string $file_name
     * @param array $target
     * @return void
     * @throws CacheFileIOException
     */
    public static function setCache(string $file_name, array $target): void
    {
        self::assertIfCacheFileIOException(!empty($file_name), "setCache filename is empty");
        self::makeDirIfNotExist($file_name);

        $target = str_replace('"', '\"', serialize($target));
        $fp = fopen($file_name, 'w+');
        self::assertIfCacheFileIOException($fp, "File Open fail");

        while (!flock($fp, LOCK_EX)) {
            usleep(1000);
        }

        self::assertIfCacheFileIOException(fwrite($fp, '<?php '), "Failed to write to file");
        self::assertIfCacheFileIOException(fwrite($fp, '$' . CACHE_VARIABLE_NAME . ' = unserialize("' . $target . '");'), "Failed to write to file");
        self::assertIfCacheFileIOException(fwrite($fp, ' ?>'), "Failed to write to file");
        self::assertIfCacheFileIOException(fclose($fp), "Failed to write to file");
    }

    /**
     * @param string $file_name
     * @return void
     * @throws CacheFileIOException
     */
    private static function makeDirIfNotExist(string $file_name): void {
        $dirname = dirname($file_name);
        if (is_dir($dirname)) {
            return;
        }

        self::assertIfCacheFileIOException(mkdir($dirname, 0755, true), "Failed to make dir");
    }

    /**
     * @param bool|resource $function_result
     * @param string $message
     * @return void
     * @throws CacheFileIOException
     */
    private static function assertIfCacheFileIOException($function_result, string $message) {
        if ($function_result === false) {
            throw new CacheFileIOException($message);
        }
    }

    /**
     * @param string $file_name
     * @param int|null $ttl
     * @return array|null
     */
    public static function getCacheIfExist(string $file_name, ?int $ttl = DEFAULT_TTL): ?array
    {
        if (!$file_name
            || !file_exists($file_name)
            || (filemtime($file_name) + $ttl) < time()) {
            return null;
        }
        include($file_name);

        $valName = CACHE_VARIABLE_NAME;

        return $$valName;
    }
}
