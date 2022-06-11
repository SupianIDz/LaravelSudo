<?php

namespace Octopy\Impersonate;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use Octopy\Impersonate\Contracts\Storage;
use Octopy\Impersonate\Exceptions\ImpersonateException;
use Octopy\Impersonate\Storage\SessionStorage;
use ReflectionClass;
use Throwable;

final class Impersonate
{
    /**
     * @var Storage
     */
    protected Storage $storage;

    /**
     * @var StatefulGuard
     */
    protected StatefulGuard $guard;

    /**
     * @var ImpersonateRepository
     */
    protected ImpersonateRepository $repository;

    /**
     * Impersonate constructor.
     */
    public function __construct()
    {
        // Set auth guard.
        $this->guard(config(
            'impersonate.guard', 'web'
        ));

        // Set storage.
        $this->storage(config(
            'impersonate.storage', 'session'
        ));

        $this->repository = new ImpersonateRepository($this);
    }

    /**
     * Set auth guard.
     *
     * @param  string $guard
     * @return $this
     */
    public function guard(string $guard) : self
    {
        $this->guard = Auth::guard($guard);

        return $this;
    }

    /**
     * @return Impersonation
     */
    public function impersonation() : Impersonation
    {
        return App::make('impersonation');
    }

    /**
     * Impersonate user.
     *
     * @param  User $impersonator
     * @param  User $impersonated
     * @return User
     * @throws ImpersonateException
     */
    public function impersonate(User $impersonator, User $impersonated) : User
    {
        if (! $this->guard->check()) {
            throw new ImpersonateException('You must be logged in to impersonate.');
        }

        // when in impersonation mode, $impersonator set to current impersonator
        if ($this->storage->isInImpersonatingMode()) {
            $impersonator = $this->getImpersonator();
        }

        // check if impersonation is allowed
        if ($this->check($impersonator, $impersonated)) {
            // set impersonator and impersonated to storage
            $this->storage
                ->setImpersonatorIdentifier($impersonator)
                ->setImpersonatedIdentifier($impersonated);

            // then, set impersonator to current user
            $this->guard->login($impersonated);
        }

        return $impersonated;
    }

    /**
     * Leave impersonation mode.
     *
     * @return bool
     */
    public function leave() : bool
    {
        if ($this->storage->isInImpersonatingMode()) {
            // first, we need set current user to impersonator
            $this->guard->login(
                $this->getImpersonator()
            );

            // then, we need to clear storage
            $this->storage->clearStorage();
        }

        return true;
    }

    /**
     * Get current authenticated user.
     *
     * @return Authenticatable|User
     */
    public function getCurrentUser() : Authenticatable|User
    {
        return $this->guard->user();
    }

    /**
     * Get current impersonator.
     *
     * @return User
     */
    public function getImpersonator() : User
    {
        return $this->repository->getImpersonatorInStorage();
    }

    /**
     * Get current impersonated user.
     *
     * @return User
     */
    public function getImpersonated() : User
    {
        return $this->repository->getImpersonatedInStorage();
    }

    /**
     * Set or get storage.
     *
     * @param  Storage|string|null $storage
     * @return Storage
     */
    public function storage(Storage|string $storage = null) : Storage
    {
        if (is_null($storage)) {
            return $this->storage;
        }

        // try to find the storage class
        // @codeCoverageIgnoreStart
        if (is_string($storage) && ! class_exists($storage)) {
            try {
                $storage = match (strtolower($storage)) {
                    'session' => SessionStorage::class,
                };
            } catch (Throwable) {
                //
            }
        }

        // @codeCoverageIgnoreEnd

        return $this->storage = ! is_string($storage) ? $storage : App::make($storage);
    }

    /**
     * Check if impersonation is allowed.
     *
     * @param  User $impersonator
     * @param  User $impersonated
     * @return bool
     * @throws ImpersonateException
     */
    private function check(User $impersonator, User $impersonated) : bool
    {
        if ($impersonator->getAuthIdentifier() === $impersonated->getAuthIdentifier()) {
            throw new ImpersonateException('You cannot impersonate yourself.');
        }

        if (! $this->impersonation()->check('impersonator', $impersonator)) {
            throw new ImpersonateException('You don\'t have the ability to impersonate.');
        }

        if (! $this->impersonation()->check('impersonated', $impersonated)) {
            throw new ImpersonateException('You can\'t impersonate this user.');
        }

        return true;
    }

    /**
     * @return bool
     */
    public function enabled() : bool
    {
        return config('impersonate.enabled', false);
    }

    /**
     * Check if current user or impersonator is authorized to impersonate.
     *
     * @return bool
     */
    public function authorized() : bool
    {
        if ($this->storage->isInImpersonatingMode()) {
            return $this->guard->check() && $this->impersonation()->check('impersonator', $this->getImpersonator());
        }

        // When not in impersonation mode, we need to check if current user can act as impersonator.
        return $this->guard->check() && $this->impersonation()->check('impersonator', $this->getCurrentUser());
    }
}
