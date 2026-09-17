// A small, self-contained Ktor-shaped app, checked into the repo so
// eval/labels.json's Kotlin entries are reproducible without an external
// download -- the same role web.php/routes.rb play for PHP/Ruby.
//
// This is a fixture for the rule library and call graph, not a project
// that runs: it is never compiled or started, only parsed by tree-sitter
// and scanned by Semgrep, the same way the other *_demo fixtures are.
fun main() {
    embeddedServer(Netty, port = 8080) {
        routing {
            route("/diagnostics") {
                get("/ping") {
                    CommandService().runPing(call.parameters["host"] ?: "")
                }
                get("/ping/safe") {
                    CommandService().runPingSafe(call.parameters["host"] ?: "")
                }
            }
        }
    }.start(wait = true)
}
