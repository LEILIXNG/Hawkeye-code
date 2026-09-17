# A small, self-contained Rails-shaped routes file with a handful of
# genuine vulnerabilities and their safe counterparts, checked into the
# repo so eval/labels.json's Ruby entries are reproducible without an
# external download -- the same role web.php plays for PHP.
#
# This is a fixture for the rule library and call graph, not a Rails app
# that boots: it is never loaded by Rails, only parsed by tree-sitter and
# scanned by Semgrep, the same way the other *_demo fixtures are.
#
# Both Ruby route-registration signals this tool recognises are exercised
# here: /ping through a per-verb get(..., to: '...') call, /users through
# the resources :users RESTful macro (narrowed to just :show, the one
# action this fixture's UsersController actually defines).
get '/ping', to: 'diagnostics#ping'
get '/ping/safe', to: 'diagnostics#ping_safe'
resources :users, only: [:show]
get '/users/safe', to: 'users#show_safe'
