/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.dslpolicyloader;

class ReportTest {
    // todo fix
    //
    //    Report report;
    //
    //    class TestRule implements Rule {
    //
    //        @Override
    //        public String getName() {
    //            return "Test Rule Name";
    //        }
    //
    //        @Override
    //        public String getDescription() {
    //            return "Test Rule Description";
    //        }
    //
    //        @Override
    //        public boolean isViolated(HttpMessage msg) {
    //            return false;
    //        }
    //    }
    //
    //    private List<String> getPolicyName() {
    //        return new ArrayList<>(Arrays.asList("Test"));
    //    }
    //
    //    private List<String> getRuleName() {
    //        return new ArrayList<>(Arrays.asList("Test_Rule"));
    //    }
    //
    //    private List<String> getDescription() {
    //        return new ArrayList<>(Arrays.asList("Test Use"));
    //    }
    //
    //    private List<TestRule> getTestRules() {
    //        TestRule testRule = new TestRule();
    //        return new ArrayList<TestRule>(Arrays.asList(testRule));
    //    }
    //
    //    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
    //        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
    //        return msg;
    //    }
    //
    //    @BeforeAll
    //    static void setup() {
    //        Constant.setZapHome("src/main/zapHomeFiles/");
    //    }
    //
    //    @Test
    //    void addViolation() throws IOException {
    //        HttpMessage testHTTPMessage = createHttpMsg();
    //        String policyName = "Test Policy Name";
    //        List<TestRule> testRuleList = getTestRules();
    //        report = new Report();
    //        for (TestRule testRule : testRuleList) {
    //            Violation violation = new Violation(policyName, testRule, testHTTPMessage);
    //            report.addViolation(violation);
    //            assertTrue(
    //                    report.toString()
    //                            .contains(
    //                                    String.format(
    //                                            "<tr><td>%s</td><td>%s</td><td><a
    // href=\"%s\">URL</a></td><td>%s</td></tr>",
    //                                            policyName,
    //                                            testRule.getName(),
    //                                            violation.getUri(),
    //                                            testRule.getDescription())));
    //        }
    //    }
    //
    //    @Test
    //    void writeToFileExists() throws IOException {
    //        String filename = System.getProperty("java.io.tmpdir") + File.separator +
    // "testreport.html";
    //        report = new Report();
    //        report.writeToFile(filename);
    //        Path path = Paths.get(filename);
    //        assertTrue(Files.exists(path));
    //        Files.delete(path);
    //    }
    //
    //    @Test
    //    void writeToFileContent() throws IOException {
    //        String filename = System.getProperty("java.io.tmpdir") + File.separator +
    // "testreport.html";
    //        HttpMessage testHTTPMessage = createHttpMsg();
    //        String policyName = "Test Policy Name";
    //        List<TestRule> testRuleList = getTestRules();
    //        report = new Report();
    //        for (TestRule testRule : testRuleList) {
    //            Violation violation = new Violation(policyName, testRule, testHTTPMessage);
    //            report.addViolation(violation);
    //        }
    //        Path path = Paths.get(filename);
    //        report.writeToFile(filename);
    //        String fileString = Files.readAllLines(path).toString();
    //        for (TestRule testRule : testRuleList) {
    //            assertTrue(
    //                    fileString.contains(
    //                            String.format(
    //                                    "<tr><td>%s</td><td>%s</td><td><a
    // href=\"%s\">URL</a></td><td>%s</td></tr>",
    //                                    policyName,
    //                                    testRule.getName(),
    //                                    testHTTPMessage.getRequestHeader().getURI().toString(),
    //                                    testRule.getDescription())));
    //        }
    //        Files.delete(path);
    //    }
}
