<?php

namespace Octopy\Impersonate\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\App;
use Octopy\Impersonate\Exceptions\ImpersonateException;
use Octopy\Impersonate\Impersonate as Manager;

trait Impersonate
{
    /**
     * @param  Authenticatable|null $user
     * @return Authenticatable|User|Manager
     * @throws ImpersonateException
     */
    public function impersonate(Authenticatable $user = null) : Authenticatable|User|Manager
    {
        /**
         * @var Manager $manager
         */
        $manager = App::make('impersonate');

        if ($user) {
            return $manager->impersonate($this, $user);
        }

        return $manager;
    }
}
