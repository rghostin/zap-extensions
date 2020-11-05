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
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.policyloader.exceptions.DuplicatePolicyException;
import org.zaproxy.zap.extension.policyloader.rules.EmailMatchingRule;
import org.zaproxy.zap.extension.policyloader.rules.HSTSRule;
import org.zaproxy.zap.extension.policyloader.rules.HTTPSRule;
import org.zaproxy.zap.extension.policyloader.rules.KeywordMatchingRule;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.scanner.PolicyScanner;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionPolicyLoader extends ExtensionAdaptor {

    private ZapMenuItem menuPolicyLoader;
    private final int SCANNER_PLUGIN_ID = 500001;
    private PolicyScanner policyScanner = null;

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // if we're not running as a daemon
        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenuPolicyLoader());
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

    private void loadRulesTest() throws DuplicatePolicyException { // todo remove
        String policyName = "testpolicy";
        Set<Rule> testRules = new HashSet<>();
        testRules.add(new KeywordMatchingRule());
        testRules.add(new HSTSRule());
        testRules.add(new EmailMatchingRule());
        testRules.add(new HTTPSRule());
        getPolicyScanner().addPolicy(policyName, testRules);
    }

    private ZapMenuItem getMenuPolicyLoader() {
        if (menuPolicyLoader == null) {
            menuPolicyLoader = new ZapMenuItem("PolicyLoader"); // TODO checkout external strings

            menuPolicyLoader.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent ae) {
                            File[] files = getSelectedJARFiles();
                            for (File file: files) {
                                // load policy from jar
                                PolicyRuleLoader policyLoader = null;
                                try {
                                    policyLoader = new PolicyRuleLoader(file.getAbsolutePath());
                                } catch (Exception e) {
                                    View.getSingleton().showMessageDialog("Error: loading policy in "+ file.getName()+".");
                                    continue;
                                }

                                // add policy to scanner
                                try {
                                    getPolicyScanner().addPolicy(
                                            policyLoader.getPolicyName(),
                                            policyLoader.getRules()
                                    );
                                } catch (DuplicatePolicyException e) {
                                    View.getSingleton().showMessageDialog("Error: Policy "+ policyLoader.getPolicyName() + " already exists.");
                                    continue;
                                }

                                View.getSingleton().showMessageDialog(" Policy "+ policyLoader.getPolicyName() + " loaded successfully.");

                            }
                        }
                    });
        }
        return menuPolicyLoader;
    }


}
