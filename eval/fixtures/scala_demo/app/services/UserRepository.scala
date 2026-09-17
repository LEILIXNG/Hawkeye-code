package services

object UserRepository {
  def findUser(username: String): String = {
    // CWE-89: the query is built by string concatenation from a
    // username argument; rules/vendor/semgrep-rules/scala/lang/security/
    // audit/tainted-sql-string.yaml matches directly (mode: taint, whose
    // pattern-sources treats any parameter of the enclosing method as a
    // source, not only an http.request access -- see rules/ruleset.yml's
    // Scala section).
    "SELECT * FROM users WHERE username = '" + username + "'"
  }

  def findUserSafe(username: String): String = {
    "SELECT * FROM users WHERE username = ?"
  }
}
