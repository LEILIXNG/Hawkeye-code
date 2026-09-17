// A small, self-contained ASP.NET Core-shaped app with a handful of
// genuine vulnerabilities and their safe counterparts, checked into the
// repo so eval/labels.json's C# entries are reproducible without an
// external download -- the same role python_demo/app.py, express_demo/
// app.js and rust_demo/main.rs play for their languages.
//
// This is a fixture for the rule library and call graph, not a project
// that builds: it is never compiled, only parsed by tree-sitter and
// scanned by Semgrep, the same way the other *_demo fixtures are.
//
// Sinks live in plain service classes rather than directly on the
// controllers: a `public` method on a Controller/ControllerBase-derived
// type is itself a convention-routed action in real ASP.NET MVC, and this
// tool's own csharp_entrypoints.py correctly treats it that way (see
// scanner/callgraph/__init__.py's C# paragraph) -- a service class avoids
// that ambiguity while still being `public`, which the vendored
// os-command-injection rule's own pattern-inside requires of the
// enclosing method.
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace App.Controllers
{
    public class DiagnosticsController : ControllerBase
    {
        [HttpGet("ping")]
        public void Ping(string host)
        {
            CommandService.RunPing(host);
        }

        [HttpGet("ping/safe")]
        public void PingSafe(string host)
        {
            CommandService.RunPingSafe(host);
        }
    }

    public class UsersController : ControllerBase
    {
        [HttpGet("users")]
        public string GetUser(string username)
        {
            return UserRepository.FindUser(username);
        }

        [HttpGet("users/safe")]
        public string GetUserSafe(string username)
        {
            return UserRepository.FindUserSafe(username);
        }
    }
}

namespace App.Services
{
    public static class CommandService
    {
        public static void RunPing(string host)
        {
            // CWE-78: the host is handed straight to Process.Start with no
            // other argument -- the shape the vendored os-command-injection
            // rule matches directly, no shell required.
            Process.Start(host);
        }

        public static void RunPingSafe(string host)
        {
            var allowed = new[] { "localhost", "127.0.0.1" };
            if (System.Array.IndexOf(allowed, host) >= 0)
            {
                Process.Start("ping", host);
            }
        }
    }

    public static class UserRepository
    {
        public static string FindUser(string username)
        {
            var connection = new System.Data.SqlClient.SqlConnection("Data Source=(local);Initial Catalog=App;");
            var command = connection.CreateCommand();
            // CWE-89: the query is built by string concatenation from a
            // request parameter, straight into CommandText.
            command.CommandText = "SELECT * FROM Users WHERE username = '" + username + "'";
            return command.CommandText;
        }

        public static string FindUserSafe(string username)
        {
            var connection = new System.Data.SqlClient.SqlConnection("Data Source=(local);Initial Catalog=App;");
            var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM Users WHERE username = @username";
            command.Parameters.AddWithValue("@username", username);
            return command.CommandText;
        }
    }

    public static class OrphanService
    {
        // Never called from anywhere -- exists to confirm the verifier (or
        // a human) reads "not reachable" here, not "not vulnerable"; the
        // sink itself is exactly as dangerous as CommandService.RunPing()'s.
        public static void OrphanVulnerableHelper(string cmd)
        {
            Process.Start(cmd);
        }
    }
}
