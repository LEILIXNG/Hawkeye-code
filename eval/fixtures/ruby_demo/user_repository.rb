class UserRepository
  # CWE-89: a raw SQL fragment built by string interpolation straight
  # from `params` is handed to ActiveRecord's `where`, which rules/vendor/
  # semgrep-rules/ruby/rails/security/injection/tainted-sql-string.yaml
  # matches directly (mode: taint, source `params`/`request`). Unlike
  # CommandService's own sink, this rule's source is `params` itself, not
  # "any parameter" -- so the reference has to be written here rather than
  # passed in as an argument, even though this is a plain service object,
  # not a controller, at runtime.
  def find_user
    User.where("username = '#{params[:username]}'")
  end

  def find_user_safe
    User.where(username: params[:username])
  end
end
