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
        if (empty($file_name)) {
            throw new CacheFileIOException("setCache filename is empty");
        }
        $target = str_replace('"', '\"', serialize($target));
        $fp = fopen($file_name, 'w+');
        if (false === $fp) {
            throw new CacheFileIOException("setCache filename is empty");
        }
        while (!flock($fp, LOCK_EX)) {
            usleep(1000);
        }

        if (false === fwrite($fp, '<?php ')) throw new CacheFileIOException("Failed to write to file");
        if (false === fwrite($fp, '$' . CACHE_VARIABLE_NAME . ' = unserialize("' . $target . '");')) throw new CacheFileIOException("Failed to write to file");
        if (false === fwrite($fp, ' ?>')) throw new CacheFileIOException("Failed to write to file");
        if (false === fclose($fp)) throw new CacheFileIOException("Failed to write to file");
    }

    /**
     * @param string $file_name
     * @param int|null $ttl
     * @return array|null
     */
    public static function getCache(string $file_name, ?int $ttl = DEFAULT_TTL): ?array
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
