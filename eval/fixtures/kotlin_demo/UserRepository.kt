class UserRepository {
    fun findUser(username: String): String {
        // CWE-89: the query is built by string concatenation from a
        // username argument, the shape rules/custom/kotlin/
        // sql-string-formatting.yml matches directly.
        return "SELECT * FROM users WHERE username = '" + username + "'"
    }

    fun findUserSafe(username: String): String {
        return "SELECT * FROM users WHERE username = ?"
    }
}
