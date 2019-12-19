<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Cache;

use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;
const CACHE_VARIABLE_NAME = 'cache_variable_name';

class CacheManager
{
    /**
     * @param string $file_name
     * @param array $target
     * @return void
     */
    public static function setCache($file_name, $target): void
    {
        if (!$file_name) {
            return;
        }
        // Serializing Targeted Data
        $target = str_replace('"', '\"', serialize($target));

        // Writing to Cache File
        $fp = fopen($file_name, 'w+');

        while (!flock($fp, LOCK_EX)) { # waiting if locked.
            var_dump("Waiting!!!");
            usleep(1000);
        }

        fwrite($fp, '<?php ');
        fwrite($fp, '$' . CACHE_VARIABLE_NAME . ' = unserialize("' . $target . '");');
        fwrite($fp, ' ?>');
        fclose($fp); //  the lock is released also by fclose() (which is also called automatically when script finished).
    }

    /**
     * @param string $file_name
     * @param int|null $ttl
     * @return array|null
     */
    public static function getCache($file_name, $ttl = 600): ?array
    {
        if(!$file_name || !file_exists($file_name) || filemtime($file_name) + $ttl < time())
        {
            return null;
        }

        include($file_name);
        $valName = CACHE_VARIABLE_NAME;
        return $$valName;
    }
}
