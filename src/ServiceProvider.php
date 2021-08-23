<?php
/**
 * Created by PhpStorm.
 * User: hugh.li
 * Date: 2021/4/18
 * Time: 10:32 下午.
 */

namespace HughCube\Laravel\Auth;

use Illuminate\Auth\AuthManager;
use Illuminate\Support\ServiceProvider as IlluminateServiceProvider;

class ServiceProvider extends IlluminateServiceProvider
{
    /**
     * Boot the provider.
     */
    public function boot()
    {
    }

    /**
     * Register the provider.
     */
    public function register()
    {
        $this->app->resolving('auth', function ($auth) {
            /** @var AuthManager $auth */
            $auth->provider('cache', function ($app, $config) {
                return new CacheProvider(
                    ($config['hash'] ?? $app['hash']),
                    ($config['cache'] ?? $app->config->get('cache.default')),
                    ($config['expiresInSeconds'] ?? (7 * 24 * 3600)),
                    ($config['cacheKeyPrefix'] ?? 'auth'),
                    ($config['cacheTags'] ?? [])
                );
            });
        });
    }
}
