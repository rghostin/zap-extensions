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
package org.zaproxy.zap.extension.reportingproxy;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;

/** Responsible for reporting rule violations Builds an HTML report */
public class Report {

    private List<String> rows = new ArrayList<>();

    private final String html_template_content;
    private static final String HTML_TEMPLATE_NAME = "report/policy_report_template.html";
    private static final String TEMPLATE_REP_VAR = "III_TABLE_CONTENT_III";

    public Report() throws IOException {
        File html_template_file = new File(Constant.getZapHome(), HTML_TEMPLATE_NAME);
        html_template_content = new String(Files.readAllBytes(html_template_file.toPath()));
    }

    /**
     * Get a string of the html template
     *
     * @return html template content
     */
    private String getTemplateContent() {
        return html_template_content;
    }

    /**
     * Add a violation to the report
     *
     * @param violation
     */
    public void addViolation(Violation violation) {
        rows.add(
                String.format(
                        "<tr><td>%s</td><td>%s</td><td><a href=\"%s\">URL</a></td><td>%s</td></tr>",
                        "--", // todo fix
                        violation.getRuleName(),
                        violation.getTriggeringUri(),
                        violation.getDescription()));
    }

    /**
     * Get the HTML table of violations
     *
     * @return
     */
    private String getTableContent() {
        StringBuilder tableContent = new StringBuilder();
        for (String row : rows) {
            tableContent.append(row).append("\n");
        }
        return tableContent.toString();
    }

    /**
     * Write HTML report to file
     *
     * @param fileName : file name and path on the filesystem
     * @throws IOException
     */
    public void writeToFile(String fileName) throws IOException {
        FileWriter fileWriter = new FileWriter(fileName);
        fileWriter.write(toString());
        fileWriter.close();
    }

    /** @return : the HTML report in string format */
    @Override
    public String toString() {
        return getTemplateContent().replaceFirst(TEMPLATE_REP_VAR, getTableContent());
    }
}
