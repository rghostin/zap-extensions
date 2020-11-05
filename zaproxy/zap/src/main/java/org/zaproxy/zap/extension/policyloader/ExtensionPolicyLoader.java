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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
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
        List<Rule> testRules = new ArrayList<>();
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
                            //                            File[] files = getSelectedJARFiles();
                            //                            for (File file: files) {
                            //                                System.out.println(file.getName());
                            //                            }

//                            try {
//                                loadRulesTest();
//                                View.getSingleton()
//                                        .showMessageDialog("Test policy successfully loaded");
//                            } catch (DuplicatePolicyException e) {
//                                View.getSingleton().showMessageDialog("Test policy already loaded");
//                            }

                            try {
                                loadPolicyJar("/home/black/WS/Group17/policyx.jar");
                            } catch (IOException e) {
                                e.printStackTrace();
                            } catch (ClassNotFoundException e) {
                                e.printStackTrace();
                            } catch (IllegalAccessException e) {
                                e.printStackTrace();
                            } catch (InstantiationException e) {
                                e.printStackTrace();
                            }

                        }
                    });
        }
        return menuPolicyLoader;
    }

    // todo manage exceptions
    private void loadPolicyJar(String pathToJar) throws IOException, ClassNotFoundException, IllegalAccessException, InstantiationException {
        JarFile jarFile = new JarFile(pathToJar);
        Enumeration<JarEntry> e = jarFile.entries();

        URL[] urls = { new URL("jar:file:" + pathToJar+"!/") };
        URLClassLoader cl = URLClassLoader.newInstance(urls);

        while (e.hasMoreElements()) {
            JarEntry je = e.nextElement();
            if(je.isDirectory() || !je.getName().endsWith(".class")){
                continue;
            }
            // -6 because of .class
            String className = je.getName().substring(0,je.getName().length()-6);
            className = className.replace('/', '.');
            System.out.println(className);
            Class<?> pluginRule = cl.loadClass(className);
            Rule rule = (Rule) pluginRule.newInstance();
            System.out.println("YEEE" + rule.getName());

        }
    }
}
