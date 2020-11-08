package org.zaproxy.zap.extension.policyloader;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportTest {

    Report report;

    class TestRule implements Rule {

        @Override
        public String getName() {
            return "Test Rule Name";
        }

        @Override
        public String getDescription() {
            return "Test Rule Description";
        }

        @Override
        public boolean isViolated(HttpMessage msg) {
            return false;
        }
    }

    private List<String> getPolicyName() {
        return new ArrayList<>(
                Arrays.asList(
                        "Test"));
    }

    private List<String> getRuleName() {
        return new ArrayList<>(
                Arrays.asList(
                        "Test_Rule"));
    }

    private List<String> getDescription() {
        return new ArrayList<>(
                Arrays.asList(
                        "Test Use"));
    }

    private List<TestRule> getTestRules() {
        TestRule testRule = new TestRule();
        return new ArrayList<TestRule>(
                Arrays.asList(testRule));
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        return msg;
    }

    @Test
    void addViolation() throws IOException {
        HttpMessage testHTTPMessage = createHttpMsg();
        String policyName = "Test Policy Name";
        List<TestRule> testRuleList = getTestRules();
        report = new Report();
        for (TestRule testRule : testRuleList ) {
            Violation violation = new Violation(policyName,testRule,testHTTPMessage);
            report.addViolation(violation);
            assertTrue(report.toString().contains(String.format(
                    "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                    , policyName, testRule.getName(), violation.getUri(), testRule.getDescription()
            )));
        }
    }

    @Test
    void writeToFileExists() throws IOException {
        String filename = System.getProperty("java.io.tmpdir") + File.separator + "testreport.html" ;
        report = new Report();
        report.writeToFile(filename);
        Path path = Paths.get(filename);
        assertTrue(Files.exists(path));
        Files.delete(path);
    }

    @Test
    void writeToFileContent() throws IOException {
        String filename = System.getProperty("java.io.tmpdir") + File.separator + "testreport.html" ;
        HttpMessage testHTTPMessage = createHttpMsg();
        String policyName = "Test Policy Name";
        List<TestRule> testRuleList = getTestRules();
        report = new Report();
        for (TestRule testRule : testRuleList ) {
            Violation violation = new Violation(policyName,testRule,testHTTPMessage);
            report.addViolation(violation);
        }
        Path path = Paths.get(filename);
        report.writeToFile(filename);
        String fileString = Files.readAllLines(path).toString();
        for (TestRule testRule : testRuleList) {
            assertTrue(fileString.contains(String.format(
                    "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                    , policyName, testRule.getName(), testHTTPMessage.getRequestHeader().getURI().toString(), testRule.getDescription()
            )));
        }
        Files.delete(path);
    }
}