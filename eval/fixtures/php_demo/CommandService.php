<?php

namespace App\Services;

class CommandService
{
    public static function runPing($host)
    {
        // CWE-78: the host is handed straight to a shell function with a
        // non-constant command line -- the shape rules/vendor/semgrep-rules/
        // php/lang/security/exec-use.yaml matches directly (a plain pattern
        // rule, not mode: taint, so no same-function $_GET/$_POST source is
        // needed for it to fire -- see rules/ruleset.yml's PHP section).
        exec("ping -c 1 " . $host);
    }

    public static function runPingSafe($host)
    {
        $allowed = ["localhost", "127.0.0.1"];
        if (in_array($host, $allowed, true)) {
            exec("ping -c 1 localhost");
        }
    }

    // Never called from anywhere -- exists to confirm the verifier (or a
    // human) reads "not reachable" here, not "not vulnerable"; the sink
    // itself is exactly as dangerous as runPing()'s. Deliberately takes a
    // plain parameter rather than reading $_GET/$_POST directly: this
    // tool's own superglobal-usage hint (see scanner/callgraph/
    // php_entrypoints.py) would otherwise mark a function reading a
    // superglobal as its own weak entry point, which is exactly the
    // ambiguity this fixture is not testing.
    public static function orphanVulnerableHelper($cmd)
    {
        exec($cmd);
    }
}
