class CommandService
  # CWE-78: the host is handed straight to a shell interpolation --
  # rules/vendor/semgrep-rules/ruby/lang/security/dangerous-exec.yaml
  # matches directly (mode: taint, but any parameter of the enclosing
  # method is itself one of its pattern-sources, alongside params/cookies
  # -- see rules/ruleset.yml's Ruby section for why that matters here: it
  # is what lets this sink fire without the source needing to be `params`
  # read in this same method). A plain instance method on purpose: the
  # rule's own `def $F(...,$ARG,...)` source pattern matches a `method`
  # node, not a `singleton_method` (`def self.foo`) -- see
  # scanner/callgraph/ruby_index.py's own docstring for that same grammar
  # distinction on the call-graph side.
  def run_ping(host)
    system("ping -c 1 #{host}")
  end

  def run_ping_safe(host)
    allowed = ["localhost", "127.0.0.1"]
    system("ping -c 1 localhost") if allowed.include?(host)
  end

  # Never called from anywhere -- exists to confirm the verifier (or a
  # human) reads "not reachable" here, not "not vulnerable"; the sink
  # itself is exactly as dangerous as run_ping()'s.
  def orphan_vulnerable_helper(cmd)
    system(cmd)
  end
end
