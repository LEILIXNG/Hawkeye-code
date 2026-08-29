// Annotated fixture for command-injection.yml, run by `semgrep --test`
// (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).
//
// Every case here is a shape this rule was measured to be the only thing
// catching, or a shape it must deliberately stay off. The `ok:` cases are
// the point of the file: this rule is scoped to shell invocation, and
// widening it until it overlaps the vendored rules would just produce a
// second candidate for the same sink.
import java.io.IOException;
import java.util.Arrays;

class CommandInjectionFixture {

    // The shape this rule exists for. The vendored
    // command-injection-process-builder rule spells out
    // `new ProcessBuilder(new String[]{"cmd","/c",$ARG,...})` but has no
    // array-form counterpart for sh/bash, so it misses this line while
    // catching the cmd line below -- verified against VulnerableApp's
    // CommandInjection.java:47 vs :52.
    void arrayFormShell(String ipAddress) throws IOException {
        // ruleid: shell-invocation-with-nonconstant-command
        new ProcessBuilder(new String[] {"sh", "-c", "ping -c 2 " + ipAddress}).start();
    }

    void arrayFormBash(String ipAddress) throws IOException {
        // ruleid: shell-invocation-with-nonconstant-command
        new ProcessBuilder(new String[] {"bash", "-c", "ping -c 2 " + ipAddress}).start();
    }

    void arrayFormCmd(String ipAddress) throws IOException {
        // ruleid: shell-invocation-with-nonconstant-command
        new ProcessBuilder(new String[] {"cmd", "/c", "ping -n 2 " + ipAddress}).start();
    }

    void varargsShell(String ipAddress) throws IOException {
        // ruleid: shell-invocation-with-nonconstant-command
        new ProcessBuilder("sh", "-c", "ping -c 2 " + ipAddress).start();
    }

    void varargsCmd(String ipAddress) throws IOException {
        // ruleid: shell-invocation-with-nonconstant-command
        new ProcessBuilder("cmd", "/c", "ping -n 2 " + ipAddress).start();
    }

    void listForm(String ipAddress) throws IOException {
        // ruleid: shell-invocation-with-nonconstant-command
        new ProcessBuilder(Arrays.asList("sh", "-c", "ping -c 2 " + ipAddress)).start();
    }

    // The command is assembled into a local first. Matching only on a
    // syntactic `$CMD + $VAR` inside the call missed this, and so does the
    // vendored rule for the sh array form -- a real hole in both.
    void concatenatedIntoLocal(String ipAddress) throws IOException {
        String command = "ping -c 2 " + ipAddress;
        // ruleid: shell-invocation-with-nonconstant-command
        new ProcessBuilder(new String[] {"sh", "-c", command}).start();
    }

    void formattedIntoLocal(String ipAddress) throws IOException {
        String command = String.format("ping -c 2 %s", ipAddress);
        // ruleid: shell-invocation-with-nonconstant-command
        new ProcessBuilder(new String[] {"sh", "-c", command}).start();
    }

    void runtimeExecArrayForm(String ipAddress) throws IOException {
        // ruleid: shell-invocation-with-nonconstant-command
        Runtime.getRuntime().exec(new String[] {"sh", "-c", "ping -c 2 " + ipAddress});
    }

    void runtimeExecVarargs(String ipAddress) throws IOException {
        // ruleid: shell-invocation-with-nonconstant-command
        Runtime.getRuntime().exec("sh", "-c", "ping -c 2 " + ipAddress);
    }

    // Fully literal command line: nothing external reaches the shell.
    void constantCommand() throws IOException {
        // ok: shell-invocation-with-nonconstant-command
        new ProcessBuilder(new String[] {"sh", "-c", "ping -c 2 127.0.0.1"}).start();
    }

    // Same, via a constant local.
    void constantInLocal() throws IOException {
        String command = "ping -c 2 127.0.0.1";
        // ok: shell-invocation-with-nonconstant-command
        new ProcessBuilder(new String[] {"sh", "-c", command}).start();
    }

    // No shell in the picture: argv goes straight to execve, so a
    // metacharacter in ipAddress is an argument and not a command. Out of
    // scope on purpose -- command-injection-process-builder already covers
    // this shape, and claiming it here would double-report the sink.
    void noShellInvolved(String ipAddress) throws IOException {
        // ok: shell-invocation-with-nonconstant-command
        new ProcessBuilder("ping", "-c", "2", ipAddress).start();
    }
}
