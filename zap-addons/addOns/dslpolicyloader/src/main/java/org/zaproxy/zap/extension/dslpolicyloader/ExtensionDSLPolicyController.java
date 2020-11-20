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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.dslpolicyloader.exceptions.DuplicatePolicyException;
import org.zaproxy.zap.extension.dslpolicyloader.exceptions.SyntaxErrorException;
import org.zaproxy.zap.extension.dslpolicyloader.parser.PolicyParser;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.view.ZapMenuItem;

/** This is a policy controller for policies of text file */
public class ExtensionDSLPolicyController extends ExtensionAdaptor {

    private ZapMenuItem menuPolicyLoader;
    private ZapMenuItem menuViewPolicies;
    private ZapMenuItem menuPolicyViolationsReport;

    private static final int SCANNER_PLUGIN_ID = 500001;
    private static final String NAME = "Policy Loader";
    protected static final String PREFIX = "dslpolicyloader";
    private PolicyScanner policyScanner = null;
    PolicyParser policyParser = new PolicyParser();

    public ExtensionDSLPolicyController() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // if we're not running as a daemon
        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenuPolicyLoader());
            extensionHook.getHookMenu().addToolsMenuItem(getMenuViewPolicies());
            extensionHook.getHookMenu().addReportMenuItem(getMenuReportPolicyViolations());
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
     * Returns the PolicyScanner
     *
     * @return Returns the PolicyScanner
     */
    private PolicyScanner getPolicyScanner() {
        if (policyScanner == null) {
            ExtensionPassiveScan extPassiveScan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionPassiveScan.class);
            policyScanner =
                    (PolicyScanner) extPassiveScan.getPluginPassiveScanner(SCANNER_PLUGIN_ID);
        }
        return policyScanner;
    }

    /**
     * Returns an array of selected policies of text files
     *
     * @return Returns an array of selected policies of text files
     */
    public File[] getSelectedTextFiles() {
        JFileChooser chooser = new JFileChooser();
        chooser.setAcceptAllFileFilterUsed(false);
        FileNameExtensionFilter filter = new FileNameExtensionFilter("*.txt", "txt", "txt");
        chooser.setFileFilter(filter);
        chooser.setMultiSelectionEnabled(true);
        chooser.showOpenDialog(View.getSingleton().getMainFrame());
        File[] files = chooser.getSelectedFiles();
        return files;
    }

    /**
     * Menu button for loading rules from text files
     *
     * @return Returns the GUI menu button
     */
    private ZapMenuItem getMenuPolicyLoader() {
        if (menuPolicyLoader == null) {
            menuPolicyLoader = new ZapMenuItem(PREFIX + ".panel.loader_title");

            menuPolicyLoader.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent ae) {
                            File[] files = getSelectedTextFiles();
                            try {
                                loadPolicyTexts(files);
                            } catch (IOException e) {
                                View.getSingleton()
                                        .showMessageDialog("Error : Unable to load files");
                            }
                        }
                    });
        }
        return menuPolicyLoader;
    }

    /**
     * Menu button for viewing active rules
     * @return: the GUI menu button
     */
    private ZapMenuItem getMenuViewPolicies() {
        if (menuViewPolicies == null) {
            menuViewPolicies = new ZapMenuItem(PREFIX + ".panel.viewpolicy_title");

            menuViewPolicies.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent ae) {
                            displayPolicies();
                        }
                    });
        }
        return menuViewPolicies;
    }

    /**
     * load text files as policies into {@code PolicyScanner} display status message (failure or
     * success)
     *
     * @param files: Array of text file objects
     */
    private void loadPolicyTexts(File[] files) throws IOException {
        StringBuilder loadedPolicyNames = new StringBuilder();
        for (File file : files) {
            String policyName = FilenameUtils.getBaseName(file.getName());
            String policyDeclaration = FileUtils.readFileToString(file, StandardCharsets.UTF_8);

            Policy policy = null;
            try {
                policy = policyParser.parsePolicy(policyDeclaration, policyName);
                getPolicyScanner().addPolicy(policy);
                loadedPolicyNames.append(policy.getName()).append("\n");
            } catch (DuplicatePolicyException e) {
                View.getSingleton()
                        .showMessageDialog(
                                "Error: Policy " + policy.getName() + " already exists.");
            } catch (SyntaxErrorException e) {
                View.getSingleton().showMessageDialog("Syntax error : " + e.getMessage());
            } catch (Exception e) {
                View.getSingleton().showMessageDialog("Error: loading policy in " + file.getName());
            }
        }

        if (!loadedPolicyNames.toString().isEmpty()) {
            View.getSingleton()
                    .showMessageDialog(
                            "Policies loaded successfully: \n" + loadedPolicyNames.toString());
        }
    }

    /**
     * Menu button for building a violations report
     *
     * @return the menu button
     */
    private ZapMenuItem getMenuReportPolicyViolations() {
        if (menuPolicyViolationsReport == null) {
            menuPolicyViolationsReport = new ZapMenuItem(PREFIX + ".panel.report_title");

            menuPolicyViolationsReport.addActionListener(
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
        return menuPolicyViolationsReport;
    }

    /**
     * Build a violation report with the violations encountered so far
     *
     * @param path : the file path of the report
     * @throws IOException
     */
    public void buildViolationsReport(String path) throws IOException {
        Report scanReport = new Report();
        for (Violation violation : getPolicyScanner().getViolationHistory()) {
            scanReport.addViolation(violation);
        }

        scanReport.writeToFile(path);
    }

    /**
     * Displays a list of policies that are active in the policyScanner
     */
    public void displayPolicies() {

        Policy[] policies = getPolicyScanner().getPolicies().toArray(new Policy[0]);
        JFrame f = new JFrame();
        final JLabel label = new JLabel();
        label.setSize(1000, 100);
        JButton b = new JButton("Show");
        b.setBounds(200, 150, 80, 30);

        final JList<Policy> list1 = new JList<>(policies);
        list1.setBounds(300, 100, 75, 75);

        f.add(list1);
        f.add(b);
        f.add(label);
        f.setSize(1000, 450);
        f.setLayout(null);
        f.setVisible(true);
        b.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        Policy selectedPolicy;
                        StringBuilder labelValue = new StringBuilder();
                        labelValue.append("Selected policy: ");
                        if (list1.getSelectedIndex() != -1) {
                            selectedPolicy = list1.getSelectedValue();
                            labelValue.append(selectedPolicy.getName());
                            List<String> ruleNames = new ArrayList<>();
                            for (Rule rule : selectedPolicy.getRules()) {
                                ruleNames.add(rule.getName());
                            }
                            labelValue
                                    .append(" - Rule names: ")
                                    .append(String.join(",", ruleNames));
                            System.out.println(labelValue.toString());
                            label.setText(labelValue.toString());
                        }
                    }
                });
    }
}
