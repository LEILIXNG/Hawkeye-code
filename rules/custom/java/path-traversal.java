// Annotated fixture for path-traversal.yml, run by `semgrep --test`
// (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).
//
// This rule exists for flows the vendored taint rules structurally cannot
// follow, so the ok: cases are mostly about staying quiet on constant
// paths. Getting those wrong is what makes a file-path rule unusable:
// almost every program opens files, and only the ones whose path has a
// non-constant segment are worth a verify call.
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.web.multipart.MultipartFile;

class PathTraversalFixture {

    // Cross-file constants do not propagate, so a path assembled purely out
    // of them still looks non-constant unless the tail is excluded. This
    // mirrors JWTUtils.KEYS_LOCATION in the corpus.
    static class Config {
        static final String KEYS_LOCATION = "/keys/";
    }

    private static final String BASE = "/scripts/PathTraversal/";

    // The VulnerableApp shape: twelve request handlers funnel a request
    // parameter into this one helper, and the read happens here. The
    // vendored tainted-file-path rule lists getResourceAsStream as a sink
    // and still misses it, because semgrep OSS taint does not cross the
    // method boundary between the handler and the helper.
    java.io.InputStream readResource(String fileName) {
        // ruleid: file-path-with-nonconstant-segment
        return this.getClass().getResourceAsStream(BASE + fileName);
    }

    java.net.URL locateResource(String fileName) {
        // ruleid: file-path-with-nonconstant-segment
        return this.getClass().getResource("/scripts/" + fileName);
    }

    java.io.InputStream readViaClassLoader(String fileName) {
        // ruleid: file-path-with-nonconstant-segment
        return this.getClass().getClassLoader().getResourceAsStream("/scripts/" + fileName);
    }

    File openFile(String fileName) {
        // ruleid: file-path-with-nonconstant-segment
        return new File("/var/data/" + fileName);
    }

    FileInputStream openStream(String fileName) throws Exception {
        // ruleid: file-path-with-nonconstant-segment
        return new FileInputStream("/var/data/" + fileName);
    }

    Path buildPath(String fileName) {
        // ruleid: file-path-with-nonconstant-segment
        return Paths.get("/var/data/" + fileName);
    }

    // The upload shape: the name comes off the multipart part, so the
    // attacker picks it. Path.resolve is a path join, so a bare variable is
    // already the traversal shape -- no concatenation needed. None of
    // resolve/transferTo appear in the vendored rule's sink list at all.
    void storeUpload(Path root, MultipartFile file) throws Exception {
        String fileName = file.getOriginalFilename();
        // ruleid: file-path-with-nonconstant-segment
        Path target = root.resolve(fileName);
        java.nio.file.Files.copy(file.getInputStream(), target);
    }

    void storeUploadDirectly(File directory, MultipartFile file) throws Exception {
        // ruleid: file-path-with-nonconstant-segment
        file.transferTo(new File(directory, file.getOriginalFilename()));
    }

    // A fully literal path.
    java.io.InputStream readFixedResource() {
        // ok: file-path-with-nonconstant-segment
        return this.getClass().getResourceAsStream("/scripts/PathTraversal/UserInfo.json");
    }

    // Assembled from constants only. The tail is a string literal, which is
    // the cheap and reliable way to tell this apart from an attacker
    // segment -- semgrep cannot see that Config.KEYS_LOCATION is constant,
    // because it lives in another compilation unit.
    java.io.InputStream readKey() {
        // ok: file-path-with-nonconstant-segment
        return this.getClass().getResourceAsStream(Config.KEYS_LOCATION + "public_crt.pem");
    }

    // Tail is a dotted constant reference rather than a local.
    Path fixedUploadRoot() {
        // ok: file-path-with-nonconstant-segment
        return Paths.get("/srv/" + Config.KEYS_LOCATION);
    }

    // A bare variable with no path join and no concatenation is not, on its
    // own, evidence of traversal -- it is every "open the file I was
    // handed" in the codebase, and the vendored taint rules already cover
    // it when the flow stays inside one method. Deliberately out of scope;
    // see the note in path-traversal.yml.
    File openWhateverWeWereGiven(String path) {
        // ok: file-path-with-nonconstant-segment
        return new File(path);
    }

    // A constant resolve segment is a fixed subdirectory.
    Path fixedSubdirectory(Path root) {
        // ok: file-path-with-nonconstant-segment
        return root.resolve("uploads");
    }
}
