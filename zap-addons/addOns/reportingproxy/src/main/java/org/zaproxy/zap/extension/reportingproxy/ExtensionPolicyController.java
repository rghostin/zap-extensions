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
import java.io.IOException;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.reportingproxy.exceptions.DuplicateRuleException;
import org.zaproxy.zap.extension.reportingproxy.rules.*;
import org.zaproxy.zap.view.ZapMenuItem;

/** This is a rules loader for policies of jar file */
public class ExtensionPolicyController extends ExtensionAdaptor {

    private ZapMenuItem menuRulesLoader;
    private ZapMenuItem menuRulesViolationsReport;

    private static final int SCANNER_PLUGIN_ID = 500001;
    private static final String NAME = "Rule Loader";
    protected static final String PREFIX = "policyloader";
    private RuleScanner ruleScanner = null;

    public ExtensionPolicyController() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // if we're not running as a daemon
        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenuRulesLoader());
            extensionHook.getHookMenu().addReportMenuItem(getMenuReportRulesViolations());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
    }

    /**
     * Returns the RulesScanner
     *
     * @return Returns the RulesScanner
     */
    private RuleScanner getRulesScanner() {
        if (ruleScanner == null) {
            ExtensionPassiveScan extPassiveScan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionPassiveScan.class);
            ruleScanner = (RuleScanner) extPassiveScan.getPluginPassiveScanner(SCANNER_PLUGIN_ID);
        }
        return ruleScanner;
    }

    /**
     * Returns an array of selected policies of jar files
     *
     * @return Returns an array of selected policies of jar files
     */
    public File[] getSelectedJARFiles() {
        JFileChooser chooser = new JFileChooser();
        chooser.setAcceptAllFileFilterUsed(false);
        FileNameExtensionFilter filter = new FileNameExtensionFilter("*.jar", "jar", "jar");
        chooser.setFileFilter(filter);
        chooser.setMultiSelectionEnabled(true);
        chooser.showOpenDialog(View.getSingleton().getMainFrame());
        File[] files = chooser.getSelectedFiles();
        return files;
    }

    /**
     * Menu button for loading rules from a jar file
     *
     * @return Returns the GUI menu button
     */
    private ZapMenuItem getMenuRulesLoader() {
        if (menuRulesLoader == null) {
            menuRulesLoader = new ZapMenuItem(PREFIX + ".panel.loader_title");

            menuRulesLoader.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent ae) {
                            //                            File[] files = getSelectedJARFiles();
                            //                            loadRulesJars(files);
                            loadRulesBatch();
                        }
                    });
        }
        return menuRulesLoader;
    }

    /**
     * load jar files as policies into {@code RulesScanner} display status message (failure or
     * success)
     *
     * @param files: Array of jar file objects
     */
    private void loadRulesJars(File[] files) {
        StringBuilder loadedRulesNames = new StringBuilder();

        for (File file : files) {
            // load rules from jar
            RulesJarLoader rulesJarLoader = null;
            try {
                rulesJarLoader = new RulesJarLoader(file.getAbsolutePath());
            } catch (Exception e) {
                View.getSingleton().showMessageDialog("Error: loading rules in " + file.getName());
                continue;
            }

            // load the rules in the scanner
            for (Rule loadedRule : rulesJarLoader.getRules()) {
                try {
                    getRulesScanner().addRule(loadedRule);
                    loadedRulesNames.append(loadedRule.getName()).append("\n");
                } catch (DuplicateRuleException e) {
                    View.getSingleton()
                            .showMessageDialog(
                                    "Error: Rule " + loadedRule.getName() + " already exists.");
                }
            }
        }

        if (!loadedRulesNames.toString().isEmpty()) {
            View.getSingleton()
                    .showMessageDialog(
                            "Policies loaded successfully: \n" + loadedRulesNames.toString());
        }
    }

    /**
     * Menu button for building a violations report
     *
     * @return the menu button
     */
    private ZapMenuItem getMenuReportRulesViolations() {
        if (menuRulesViolationsReport == null) {
            menuRulesViolationsReport = new ZapMenuItem(PREFIX + ".panel.report_title");

            menuRulesViolationsReport.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent ae) {
                            String path;

                            JFileChooser fileChooser = new JFileChooser();
                            int option =
                                    fileChooser.showSaveDialog(View.getSingleton().getMainFrame());
                            if (option == JFileChooser.APPROVE_OPTION) {
                                path = fileChooser.getSelectedFile().getAbsolutePath();
                            } else {
                                // canceled
                                return;
                            }

                            try {
                                buildViolationsReport(path);
                                View.getSingleton().showMessageDialog("Report built: " + path);
                            } catch (IOException e) {
                                View.getSingleton().showMessageDialog("Error building report");
                            }
                        }
                    });
        }
        return menuRulesViolationsReport;
    }

    /**
     * Build a violation report with the violations encountered so far
     *
     * @param path : the file path of the report
     * @throws IOException
     */
    public void buildViolationsReport(String path) throws IOException {
        Report scanReport = new Report();
        for (Violation violation : getRulesScanner().getViolationHistory()) {
            scanReport.addViolation(violation);
        }

        scanReport.writeToFile(path);
    }

    // todo remove
    private void loadRulesBatch() {
        try {
            getRulesScanner().addRule(new KeywordMatchingRule());
            getRulesScanner().addRule(new ThresholdRule());
            getRulesScanner().addRule(new CommonHeadersRule());
            getRulesScanner().addRule(new RequestPerformanceRule());
            getRulesScanner().addRule(new HiddenFieldRule());
            View.getSingleton().showMessageDialog("Loaded btach rules sucessfully");
        } catch (DuplicateRuleException e) {
            View.getSingleton().showMessageDialog("Error cannot load batch rules");
        }
    }
}
