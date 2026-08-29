// Annotated fixture for xxe-jaxb.yml, run by `semgrep --test`
// (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).
//
// The `ok:` cases carry most of the weight here. Both rules in this file
// fire on code that *looks* hardened, so the thing that can silently break
// is the subtraction: saxparserfactory-general-entities-only must go quiet
// once the parameter-entity or DOCTYPE feature is also set, and
// jaxb-unmarshal-of-request-stream must go quiet once the stream is wrapped
// in a SAXSource. A regression there turns a fix into a reported finding.
import java.io.InputStream;
import java.io.Reader;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.sax.SAXSource;
import org.xml.sax.InputSource;

class XxeJaxbFixture {

    void unmarshalRequestStreamDirectly(HttpServletRequest request, Unmarshaller u)
            throws Exception {
        // ruleid: jaxb-unmarshal-of-request-stream
        u.unmarshal(request.getInputStream());
    }

    void unmarshalRequestReaderDirectly(HttpServletRequest request, Unmarshaller u)
            throws Exception {
        // ruleid: jaxb-unmarshal-of-request-stream
        u.unmarshal(request.getReader());
    }

    // VulnerableApp's XXEVulnerability.java LEVEL_1 shape: the stream is
    // parked in a local before it reaches the unmarshaller.
    void unmarshalRequestStreamViaLocal(HttpServletRequest request, Unmarshaller u)
            throws Exception {
        InputStream in = request.getInputStream();
        // ruleid: jaxb-unmarshal-of-request-stream
        u.unmarshal(in);
    }

    void unmarshalRequestReaderViaLocal(HttpServletRequest request, Unmarshaller u)
            throws Exception {
        Reader in = request.getReader();
        // ruleid: jaxb-unmarshal-of-request-stream
        u.unmarshal(in);
    }

    // The fix, not the finding: the stream is read through a parser the
    // caller configured, so entity handling is no longer JAXB's default.
    void unmarshalThroughSaxSource(HttpServletRequest request, Unmarshaller u, SAXParserFactory spf)
            throws Exception {
        InputStream in = request.getInputStream();
        // ok: jaxb-unmarshal-of-request-stream
        u.unmarshal(new SAXSource(spf.newSAXParser().getXMLReader(), new InputSource(in)));
    }

    // Not request-borne XML at all.
    void unmarshalLocalResource(Unmarshaller u, InputStream bundled) throws Exception {
        // ok: jaxb-unmarshal-of-request-stream
        u.unmarshal(bundled);
    }

    // LEVEL_2: general entities off, parameter entities still on. Parameter
    // entities alone are enough to read a local file and exfiltrate it, so
    // this is hardening that does not close XXE.
    void disablesGeneralEntitiesOnly(SAXParserFactory spf) throws Exception {
        // ruleid: saxparserfactory-general-entities-only
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    }

    // LEVEL_3: both entity classes disabled.
    void disablesGeneralAndParameterEntities(SAXParserFactory spf) throws Exception {
        // ok: saxparserfactory-general-entities-only
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    }

    // The blunter fix: no DOCTYPE at all.
    void disallowsDoctype(SAXParserFactory spf) throws Exception {
        // ok: saxparserfactory-general-entities-only
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    }

    // Order must not matter: the hardening can be set up before the general
    // entity feature is touched.
    void disallowsDoctypeFirst(SAXParserFactory spf) throws Exception {
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: saxparserfactory-general-entities-only
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    }
}
