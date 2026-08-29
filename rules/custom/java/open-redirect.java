// Annotated fixture for open-redirect.yml, run by `semgrep --test`
// (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).
//
// The two vendored redirect rules only know the Servlet API
// (response.sendRedirect / response.addHeader("Location", ...)) and Spring
// MVC's view-name convention ("redirect:" + url, ModelAndView). A Spring
// @RestController has neither: it builds the Location header itself, on
// HttpHeaders or on the ResponseEntity builder. Those shapes are what this
// rule adds, and the last ok: case is the boundary between the two.
import java.net.URI;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

class OpenRedirectFixture {

    // VulnerableApp names the header through a constant field rather than a
    // literal. Semgrep propagates it, which is the only reason the rule can
    // be written against "Location" instead of matching every header key.
    private static final String LOCATION_HEADER_KEY = "Location";

    ResponseEntity<?> multiValueMapEntryViaConstant(String urlToRedirect) {
        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.put(LOCATION_HEADER_KEY, new java.util.ArrayList<>());
        // ruleid: spring-location-header-from-nonconstant-url
        headers.get(LOCATION_HEADER_KEY).add(urlToRedirect);
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    ResponseEntity<?> multiValueMapEntryViaLiteral(String urlToRedirect) {
        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.put("Location", new java.util.ArrayList<>());
        // ruleid: spring-location-header-from-nonconstant-url
        headers.get("Location").add(urlToRedirect);
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    ResponseEntity<?> httpHeadersAdd(String urlToRedirect) {
        HttpHeaders headers = new HttpHeaders();
        // ruleid: spring-location-header-from-nonconstant-url
        headers.add("Location", urlToRedirect);
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    // Header names are case-insensitive on the wire and code spells them
    // both ways.
    ResponseEntity<?> httpHeadersAddLowercase(String urlToRedirect) {
        HttpHeaders headers = new HttpHeaders();
        // ruleid: spring-location-header-from-nonconstant-url
        headers.add("location", urlToRedirect);
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    // Spring's own constant, which lives in HttpHeaders and so is not
    // propagated from anything in this file.
    ResponseEntity<?> httpHeadersSetViaSpringConstant(String urlToRedirect) {
        HttpHeaders headers = new HttpHeaders();
        // ruleid: spring-location-header-from-nonconstant-url
        headers.set(HttpHeaders.LOCATION, urlToRedirect);
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    ResponseEntity<?> httpHeadersSetLocation(String urlToRedirect) {
        HttpHeaders headers = new HttpHeaders();
        // ruleid: spring-location-header-from-nonconstant-url
        headers.setLocation(URI.create(urlToRedirect));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    // The ResponseEntity builder, the shape VulnerableApp's LEVEL_11 uses.
    ResponseEntity<String> builderHeader(String urlToRedirect) {
        // ruleid: spring-location-header-from-nonconstant-url
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", urlToRedirect).build();
    }

    ResponseEntity<String> builderLocation(String urlToRedirect) {
        // ruleid: spring-location-header-from-nonconstant-url
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(urlToRedirect)).build();
    }

    // A fixed redirect target cannot be steered by a request.
    ResponseEntity<?> constantTarget() {
        HttpHeaders headers = new HttpHeaders();
        // ok: spring-location-header-from-nonconstant-url
        headers.add("Location", "/VulnerableApp/");
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    ResponseEntity<String> builderConstantTarget() {
        // ok: spring-location-header-from-nonconstant-url
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", "/").build();
    }

    // Some other header carrying a request value is not a redirect.
    ResponseEntity<?> unrelatedHeader(String requestId) {
        HttpHeaders headers = new HttpHeaders();
        // ok: spring-location-header-from-nonconstant-url
        headers.add("X-Request-Id", requestId);
        return new ResponseEntity<>(headers, HttpStatus.OK);
    }

    // The Servlet API path belongs to the vendored unvalidated-redirect
    // rule. Claiming it here would put a second rule_id on a candidate that
    // already has one, and teach nothing new.
    void servletRedirect(HttpServletResponse response, String urlToRedirect) throws Exception {
        // ok: spring-location-header-from-nonconstant-url
        response.sendRedirect(urlToRedirect);
    }
}
