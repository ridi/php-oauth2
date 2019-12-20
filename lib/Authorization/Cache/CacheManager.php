<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Cache;

use Ridibooks\OAuth2\Authorization\Exception\CacheFileIOException;

const DEFAULT_TTL = 600;

class CacheManager
{
    /**
     * @param string $file_path
     * @param array $target
     * @return void
     * @throws CacheFileIOException
     */
    public static function setCache(string $file_path, array $target): void
    {
        self::assertIfCacheFileIOException(!empty($file_path), "setCache filename is empty");
        self::makeDirIfNotExist($file_path);

        $fp = fopen($file_path, 'w+');
        self::assertIfCacheFileIOException($fp, "File Open fail");
        while (!flock($fp, LOCK_EX)) {
            usleep(1000);
        }

        self::assertIfCacheFileIOException(fwrite($fp, json_encode($target)), "Failed to write to file");
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
     * @param string $file_path
     * @param int|null $ttl
     * @return array|null
     * @throws CacheFileIOException
     */
    public static function getCacheIfExist(string $file_path, ?int $ttl = DEFAULT_TTL): ?array
    {
        if (!$file_path
            || !file_exists($file_path)
            || (filemtime($file_path) + $ttl) < time()) {
            return null;
        }
        $file = file_get_contents($file_path);
        self::assertIfCacheFileIOException($file, "File Load fail");

        return json_decode($file, true);;
    }
}
