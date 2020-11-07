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
package org.zaproxy.zap.extension.policyloader;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class Report {

    private List<String> rows = new ArrayList<>();

    private String html_template_content;

    public Report() throws IOException {
        File html_template_file =
                new File(
                        Report.class
                                .getResource("/resource/policy_report_template.html")
                                .getFile());
        html_template_content = new String(Files.readAllBytes(html_template_file.toPath()));
    }

    private String getTemplateContent() {
        return html_template_content;
    }

    public void addViolation(String policyName, String ruleName, String description) {
        rows.add(
                "<tr>\n"
                        + "    <td>"
                        + policyName
                        + "</td>\n"
                        + "    <td>"
                        + ruleName
                        + "</td>\n"
                        + "    <td>"
                        + description
                        + "</td>\n"
                        + "  </tr>");
    }

    private String getTableContent() {
        StringBuilder tableContent = new StringBuilder();
        for (String row : rows) {
            tableContent.append(tableContent).append(row);
        }
        return tableContent.toString();
    }

    public void writeToFile(String fileName) {
        try {
            FileWriter fileWriter = new FileWriter(fileName);
            fileWriter.write(toString());
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String toString() {
        return getTemplateContent();
    }

    public static void main(String[] args) throws IOException {
        Report r = new Report();
        System.out.println(r.toString());
    }
}
