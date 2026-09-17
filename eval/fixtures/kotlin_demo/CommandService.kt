class CommandService {
    fun runPing(host: String) {
        // CWE-78: the host is concatenated straight into Runtime.exec(),
        // the shape rules/vendor/semgrep-rules/kotlin/lang/security/
        // command-injection-formatted-runtime-call.yaml matches directly
        // (a plain pattern rule, not mode: taint).
        Runtime.getRuntime().exec("ping -c 1 " + host)
    }

    fun runPingSafe(host: String) {
        val allowed = listOf("localhost", "127.0.0.1")
        if (allowed.contains(host)) {
            Runtime.getRuntime().exec("ping -c 1 localhost")
        }
    }

    // Never called from anywhere -- exists to confirm the verifier (or a
    // human) reads "not reachable" here, not "not vulnerable"; the sink
    // itself is exactly as dangerous as runPing()'s.
    fun orphanVulnerableHelper(cmd: String) {
        Runtime.getRuntime().exec("sh -c " + cmd)
    }
}
