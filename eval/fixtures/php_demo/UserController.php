<?php

namespace App\Http\Controllers;

use App\Services\UserRepository;

// Registered in web.php via Route::get('/users', [UserController::class,
// 'show']) -- a plain, un-annotated class, the same "route registration
// resolves a handler declared in another file" shape web.php's own header
// comment describes.
class UserController
{
    public function show($connection, $username)
    {
        return UserRepository::findUser($connection, $username);
    }

    public function showSafe($connection, $username)
    {
        return UserRepository::findUserSafe($connection, $username);
    }
}
