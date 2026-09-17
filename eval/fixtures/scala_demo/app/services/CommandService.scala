package services

import sys.process._

// This is a fixture for the rule library and call graph, not a Play
// project that runs: it is never compiled or booted, only parsed by
// tree-sitter and scanned by Semgrep, the same way the other *_demo
// fixtures are.
object CommandService {
  def runPing(host: String): Unit = {
    // CWE-78: the host is handed straight to a shell -- the shape
    // rules/vendor/semgrep-rules/scala/lang/security/audit/
    // dangerous-shell-run.yaml matches directly (a plain pattern rule,
    // not mode: taint).
    Seq("sh", "-c", host).!!
  }

  def runPingSafe(host: String): Unit = {
    val allowed = Seq("localhost", "127.0.0.1")
    if (allowed.contains(host)) {
      Seq("ping", "-c", "1", "localhost").!!
    }
  }

  // Never called from anywhere -- exists to confirm the verifier (or a
  // human) reads "not reachable" here, not "not vulnerable"; the sink
  // itself is exactly as dangerous as runPing()'s.
  def orphanVulnerableHelper(cmd: String): Unit = {
    Seq("sh", "-c", cmd).!!
  }
}
