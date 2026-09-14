// Annotated fixture for ssrf.yml, run by `semgrep --test`
// (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).
//
// This rule exists for flows the vendored tainted-url-host rule structurally
// cannot follow (it is intraprocedural; see ssrf.yml's header), so the ok:
// cases are mostly about staying quiet on a fully constant URL.
import java.io.IOException;
import java.net.URL;

class SsrfFixture {

    void inlinePlus(String host) throws IOException {
        // ruleid: url-from-nonconstant-segment
        URL endpoint = new URL("http://" + host + "/status");
        endpoint.openStream().close();
    }

    void inlineConcat(String host) throws IOException {
        // ruleid: url-from-nonconstant-segment
        URL endpoint = new URL("http://".concat(host).concat("/status"));
        endpoint.openStream().close();
    }

    void inlineFormat(String host) throws IOException {
        // ruleid: url-from-nonconstant-segment
        URL endpoint = new URL(String.format("http://%s/status", host));
        endpoint.openStream().close();
    }

    // The HA_Benchmark-suite-412cases shape: the URL is built into a local
    // one statement before `new URL(...)`, and this rule's match is
    // anchored on whichever call actually issues the request --
    // openStream() or openConnection() -- one or two statements after that,
    // rather than on the constructor call itself.
    void plusIntoLocal(String host) throws IOException {
        String endpointUrl = "http://" + host + "/v1/state";
        URL endpoint = new URL(endpointUrl);
        // ruleid: url-from-nonconstant-segment
        endpoint.openStream().close();
    }

    void concatIntoLocal(String host) throws IOException {
        String endpointUrl = "http://".concat(host).concat("/v1/state");
        URL endpoint = new URL(endpointUrl);
        // ruleid: url-from-nonconstant-segment
        endpoint.openConnection().getInputStream().close();
    }

    // The other shape in the corpus: openConnection() assigned to its own
    // local first, then read one statement later. The sink this rule
    // matches is the openConnection() call, one statement after
    // `new URL(...)` rather than two.
    void connectionIntoLocal(String host) throws IOException {
        String endpointUrl = "http://" + host + "/health";
        URL endpoint = new URL(endpointUrl);
        // ruleid: url-from-nonconstant-segment
        java.net.URLConnection connection = endpoint.openConnection();
        connection.getInputStream().close();
    }

    void formattedIntoLocal(String host) throws IOException {
        String endpointUrl = String.format("http://%s/v1/state", host);
        URL endpoint = new URL(endpointUrl);
        // ruleid: url-from-nonconstant-segment
        endpoint.openStream().close();
    }

    void stringBuilderIntoLocal(String host) throws IOException {
        StringBuilder endpointUrlBuffer = new StringBuilder("http://");
        endpointUrlBuffer.append(host).append("/v1/state");
        String endpointUrl = endpointUrlBuffer.toString();
        URL endpoint = new URL(endpointUrl);
        // ruleid: url-from-nonconstant-segment
        endpoint.openStream().close();
    }

    // Fully literal URL: nothing external reaches it.
    void constantUrl() throws IOException {
        // ok: url-from-nonconstant-segment
        URL endpoint = new URL("http://internal.example.com/v1/state");
        endpoint.openStream().close();
    }

    // Same, assembled from literals through a local first.
    void constantIntoLocalIndirected() throws IOException {
        String endpointUrl = "http://" + "internal.example.com" + "/v1/state";
        // ok: url-from-nonconstant-segment
        URL endpoint = new URL(endpointUrl);
        endpoint.openStream().close();
    }
}
