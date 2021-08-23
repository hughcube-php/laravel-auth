<?php
/**
 * Created by PhpStorm.
 * User: hugh.li
 * Date: 2021/4/20
 * Time: 4:19 下午.
 */

namespace HughCube\Laravel\Package;

use Closure;
use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Support\Manager as IlluminateManager;
use InvalidArgumentException;

/**
 * @mixin Driver
 */
class Manager extends IlluminateManager
{
    /**
     * @param  callable|ContainerContract|null  $container
     */
    public function __construct($container = null)
    {
        $this->container = $container;
    }

    /**
     * @return ContainerContract
     */
    public function getContainer(): ContainerContract
    {
        if (is_callable($this->container)) {
            return call_user_func($this->container);
        }

        if (null === $this->container) {
            return IlluminateContainer::getInstance();
        }

        return $this->container;
    }

    /**
     * @return Repository|mixed
     * @throws BindingResolutionException
     */
    public function getConfig($name = null, $default = null)
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->getContainer()->make('config');

        if (null === $name) {
            return $config;
        }

        $key = sprintf("%s.%s", Package::getFacadeAccessor(), $name);
        return $config->get($key, $default);
    }

    /**
     * @inheritDoc
     * @throws BindingResolutionException
     */
    public function getDefaultDriver(): string
    {
        return $this->getConfig("default", "default");
    }

    /**
     * Get the configuration for a store.
     *
     * @param  string|null  $name
     *
     * @return array
     * @throws InvalidArgumentException|BindingResolutionException
     */
    protected function configuration(string $name = null): array
    {
        $name = $name ?: $this->getDefaultDriver();
        $config = $this->getConfig("drivers", []);

        if (null === $config) {
            throw new InvalidArgumentException("Driver [{$name}] not configured.");
        }

        return array_merge($config, $this->getConfig()->get("defaults", []));
    }

    /**
     * @param  string  $driver
     * @return Driver
     * @throws BindingResolutionException
     */
    protected function createDriver($driver): Driver
    {
        //return $this->resolve($driver);
        return new Driver($this->configuration($driver));
    }

    /**
     * Resolve the given store.
     *
     * @param  string  $name
     * @return mixed
     *
     * @throws InvalidArgumentException
     * @throws BindingResolutionException
     */
    protected function resolve(string $name)
    {
        $config = $this->configuration($name);

        if (isset($this->customCreators[$config['driver']])) {
            return $this->callCustomCreator($config);
        }

        $driverMethod = 'create'.ucfirst($config['driver']).'Driver';
        if (method_exists($this, $driverMethod)) {
            return $this->{$driverMethod}($config);
        }

        throw new InvalidArgumentException("Driver [{$config['driver']}] is not supported.");
    }

    /**
     * @inheritDoc
     */
    public function extend($driver, Closure $callback)
    {
        return parent::extend($driver, $callback->bindTo($this, $this));
    }
}
