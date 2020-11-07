package org.zaproxy.zap.extension.pscan.scanner;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Report {

    private List<String> rows = new ArrayList<>();

    public void addViolation(String policyName, String ruleName, String description) {
        rows.add("<tr>\n" +
                "    <td>" + policyName + "</td>\n" +
                "    <td>" + ruleName + "</td>\n" +
                "    <td>" + description + "</td>\n" +
                "  </tr>"
        );
    }

    public String getTableContent() {
        StringBuilder tableContent = new StringBuilder();
        for (String row : rows) {
            tableContent.append(tableContent).append(row);
        }
        return tableContent.toString();
    }

    public void writeToFile(String fileName) {
        try {
            // Add path here
            String path = "/Users/dalpsavaskan/IdeaProjects/Group17/zaproxy/zap/src/main/java/org/zaproxy/zap/extension/pscan/scanner/";
            FileWriter fileWriter = new FileWriter(path + fileName);
            fileWriter.write(toString());
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String toString() {
        StringBuilder htmlBuilder = new StringBuilder();
        htmlBuilder.append(htmlBuilder).append(HTML_TEMPLATE);
        htmlBuilder.append(htmlBuilder).append(getTableContent());
        htmlBuilder.append(htmlBuilder).append("</table>\n");
        htmlBuilder.append(htmlBuilder).append("</body>\n");
        htmlBuilder.append(htmlBuilder).append("</html>");
        return htmlBuilder.toString();
    }

    private String HTML_TEMPLATE = "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head>\n" +
            "<style>\n" +
            "table {\n" +
            "  font-family: arial, sans-serif;\n" +
            "  border-collapse: collapse;\n" +
            "  width: 100%;\n" +
            "}\n" +
            "\n" +
            "td, th {\n" +
            "  border: 1px solid #dddddd;\n" +
            "  text-align: left;\n" +
            "  padding: 8px;\n" +
            "}\n" +
            "\n" +
            "tr:nth-child(even) {\n" +
            "  background-color: #dddddd;\n" +
            "}\n" +
            "</style>\n" +
            "</head>\n" +
            "<body>\n" +
            "\n" +
            "<h2>HTML Table</h2>\n" +
            "\n" +
            "<table>\n" +
            "  <tr>\n" +
            "    <th>Policy Name</th>\n" +
            "    <th>Rule Name</th>\n" +
            "    <th>Description</th>\n" +
            "  </tr>  \n";
            /**+
            "</table>\n" +
            "\n" +
            "</body>\n" +
            "</html>\n" +
            "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head>\n" +
            "<style>\n" +
            "table {\n" +
            "  font-family: arial, sans-serif;\n" +
            "  border-collapse: collapse;\n" +
            "  width: 100%;\n" +
            "}\n" +
            "\n" +
            "td, th {\n" +
            "  border: 1px solid #dddddd;\n" +
            "  text-align: left;\n" +
            "  padding: 8px;\n" +
            "}\n" +
            "\n" +
            "tr:nth-child(even) {\n" +
            "  background-color: #dddddd;\n" +
            "}\n" +
            "</style>\n" +
            "</head>\n" +
            "<body>\n" +
            "\n" +
            "<h2>HTML Table</h2>\n" +
            "\n" +
            "<table>\n" +
            "  <tr>\n" +
            "    <th>Policy Name</th>\n" +
            "    <th>Rule Name</th>\n" +
            "    <th>Description</th>\n" +
            "  </tr>  ";**/

}
