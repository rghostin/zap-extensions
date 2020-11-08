package org.zaproxy.zap.extension.policyloader;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReportTest {

    Report report;

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

    @Test
    void addViolation() throws IOException {
        Iterator<String> policyI = getPolicyName().iterator();
        Iterator<String> ruleI = getRuleName().iterator();
        Iterator<String> descriptionI = getDescription().iterator();
        report = new Report();
        while(policyI.hasNext() && ruleI.hasNext() && descriptionI.hasNext()){
            String policyName = policyI.next();
            String ruleName = ruleI.next();
            String description = descriptionI.next();
            report.addViolation(policyName,ruleName,description);
            assertTrue(report.toString().contains(String.format(
                    "<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
                    , policyName, ruleName, description
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
        Iterator<String> policyI = getPolicyName().iterator();
        Iterator<String> ruleI = getRuleName().iterator();
        Iterator<String> descriptionI = getDescription().iterator();
        report = new Report();
        while(policyI.hasNext() && ruleI.hasNext() && descriptionI.hasNext()){
            String policyName = policyI.next();
            String ruleName = ruleI.next();
            String description = descriptionI.next();
            report.addViolation(policyName,ruleName,description);
        }
        Path path = Paths.get(filename);
        report.writeToFile(filename);
        while(policyI.hasNext() && ruleI.hasNext() && descriptionI.hasNext()){
            String policyName = policyI.next();
            String ruleName = ruleI.next();
            String description = descriptionI.next();
            assertTrue(report.toString().contains(String.format(
                    "<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
                    , policyName, ruleName, description
            )));
        }
        Files.delete(path);
    }
}