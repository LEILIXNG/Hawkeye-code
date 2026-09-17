# Annotated fixture for sql-string-formatting.yml, run by `semgrep --test`
# (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).
#
# This rule exists for the shape the vendored tainted-sql-string rule
# cannot see: the tainted segment arrives as a plain parameter of a
# service/DAO method, not as a literal flask.request.* access or a route
# handler's own argument. The ok: cases are mostly about staying quiet on
# a fully constant statement.


class AuthenticationService:
    # The MediChain shape this rule was added for: username is an ordinary
    # method parameter, already pulled off the request by the Flask view
    # function that calls login() -- tainted-sql-string never sees it.
    def login(self, username, password):
        # ruleid: sql-string-built-from-nonconstant-segment
        query = f"SELECT * FROM users WHERE username = '{username}'"
        return db_manager.execute_raw_sql(query)

    def get_user_by_id(self, user_id):
        # ruleid: sql-string-built-from-nonconstant-segment
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return db_manager.execute_raw_sql(query)

    def update_last_login(self, user_id, timestamp):
        # ruleid: sql-string-built-from-nonconstant-segment
        query = "UPDATE users SET last_login = '%s' WHERE id = %s" % (timestamp, user_id)
        return db_manager.execute_raw_sql(query)

    def search(self, term):
        # ruleid: sql-string-built-from-nonconstant-segment
        query = "SELECT * FROM users WHERE name LIKE '{}'".format(term)
        return db_manager.execute_raw_sql(query)

    def concat(self, term):
        # ruleid: sql-string-built-from-nonconstant-segment
        query = "SELECT * FROM users WHERE name = '" + term + "'"
        return db_manager.execute_raw_sql(query)

    # A fully literal statement carries no external input. No %/format/+
    # equivalent is exercised here: unlike the f-string pattern (which only
    # matches when there is at least one `{...}` to interpolate), the
    # %/format/+ shapes below match a fully-constant right-hand side too --
    # the same trade-off command-injection.yml and path-traversal.yml
    # already accept for their own location-only patterns, not something
    # this rule tries to special-case away.
    def list_active(self):
        # ok: sql-string-built-from-nonconstant-segment
        query = f"SELECT * FROM users WHERE active = true"
        return db_manager.execute_raw_sql(query)

    # Not SQL-shaped at all -- the keyword check is what keeps this rule
    # off every other f-string/format call in a codebase.
    def greeting(self, name):
        # ok: sql-string-built-from-nonconstant-segment
        message = f"Welcome back, {name}!"
        return message
