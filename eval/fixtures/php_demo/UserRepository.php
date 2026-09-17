<?php

namespace App\Services;

use Doctrine\DBAL\Connection;

class UserRepository
{
    public static function findUser(Connection $connection, $username)
    {
        // CWE-89: the query is built by string concatenation from a
        // username argument, straight into Connection::executeQuery() --
        // the shape rules/vendor/semgrep-rules/php/doctrine/security/audit/
        // doctrine-dbal-dangerous-query.yaml matches directly (a plain
        // pattern rule keyed on the Doctrine\DBAL\Connection import above,
        // not mode: taint).
        $sql = "SELECT * FROM users WHERE username = '" . $username . "'";
        return $connection->executeQuery($sql);
    }

    public static function findUserSafe(Connection $connection, $username)
    {
        return $connection->executeQuery("SELECT * FROM users WHERE username = ?", [$username]);
    }
}
