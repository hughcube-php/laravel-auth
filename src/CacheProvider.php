<?php
/**
 * Created by PhpStorm.
 * User: hugh.li
 * Date: 2021/8/23
 * Time: 14:33
 */

namespace HughCube\Laravel\Auth;

use BadMethodCallException;
use Carbon\Carbon;
use Illuminate\Auth\GenericUser;
use Illuminate\Cache\TaggableStore;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Psr\SimpleCache\InvalidArgumentException;

class CacheProvider implements UserProvider
{
    /**
     * @var string
     */
    protected $cacheKeyPrefix;

    /**
     * @var int
     */
    protected $expiresInSeconds;

    /**
     * @var array
     */
    protected $cacheTags;

    /**
     * @var string|Repository
     */
    protected $cache;

    /**
     * The hasher implementation.
     *
     * @var Hasher
     */
    protected $hasher;

    /**
     * @param  HasherContract  $hasher
     * @param  string|Repository  $cache
     * @param  int  $expiresInSeconds
     * @param  string  $cacheKeyPrefix
     * @param  array  $cacheTags
     */
    public function __construct(
        HasherContract $hasher,
        $cache,
        int $expiresInSeconds,
        string $cacheKeyPrefix,
        array $cacheTags
    ) {
        $this->hasher = $hasher;
        $this->cache = $cache;
        $this->expiresInSeconds = $expiresInSeconds;
        $this->cacheKeyPrefix = $cacheKeyPrefix;
        $this->cacheTags = $cacheTags;
    }

    /**
     * @throws BadMethodCallException
     */
    public function retrieveById($identifier)
    {
        throw new BadMethodCallException('Do not implement!');
    }

    /**
     * @throws BadMethodCallException
     */
    public function retrieveByToken($identifier, $token)
    {
        throw new BadMethodCallException('Do not implement!');
    }

    /**
     * @throws InvalidArgumentException
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        $cacheKey = $this->buildUserTokenCacheKey($token);

        $this->store()->set(
            $cacheKey,
            $this->getGenericUser([
                $user->getAuthIdentifierName() => $user->getAuthIdentifier(),
                $user->getRememberTokenName() => $token,
                'password' => $user->getAuthPassword(),
            ]),
            Carbon::now()->addSeconds($this->expiresInSeconds)
        );
    }

    /**
     * @param  array  $credentials
     * @return Authenticatable|null
     * @throws InvalidArgumentException
     */
    public function retrieveByCredentials(array $credentials)
    {
        $user = null;
        foreach ($credentials as $key => $value) {
            if (Str::contains($key, 'password')) {
                continue;
            }

            $user = $this->store()->get($this->buildUserTokenCacheKey($value));
            break;
        }

        $user = $user instanceof Authenticatable ? $user : null;

        if (!empty($credentials['password']) && $user instanceof Authenticatable) {
            if (!$this->validateCredentials($user, $credentials)) {
                return null;
            }
        }

        return $user;
    }

    public function validateCredentials(Authenticatable $user, array $credentials): bool
    {
        return $this->hasher->check($credentials['password'], $user->getAuthPassword());
    }

    protected function store(): Repository
    {
        $store = $this->cache instanceof Repository ? $this->cache : Cache::store($this->cache);
        return $store instanceof TaggableStore ? $store->tags($this->cacheTags) : $store;
    }

    protected function buildUserTokenCacheKey(string $token): string
    {
        return $this->buildCacheKey(sprintf('%s:%s', 'auth:token', $token));
    }

    protected function buildCacheKey(string $key): string
    {
        return sprintf('%s:%s', $this->cacheKeyPrefix, $key);
    }

    /**
     * @param  array  $user
     * @return GenericUser
     */
    public function getGenericUser(array $user): GenericUser
    {
        return new GenericUser($user);
    }
}
