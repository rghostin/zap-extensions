package org.zaproxy.zap.extension.policyloader;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.policyloader.exceptions.DuplicatePolicyException;
import org.zaproxy.zap.extension.policyloader.rules.CookieAttrRule;
import org.zaproxy.zap.extension.policyloader.rules.HSTSRule;
import org.zaproxy.zap.extension.policyloader.rules.HTTPSRule;
import org.zaproxy.zap.extension.policyloader.rules.KeywordMatchingRule;
import org.zaproxy.zap.extension.policyloader.rules.EmailMatchingRule;
import org.zaproxy.zap.extension.policyloader.rules.DomainMatchingRule;
import org.zaproxy.zap.extension.policyloader.rules.ExpectCTRule;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.scanner.PolicyScanner;
import org.zaproxy.zap.view.ZapMenuItem;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

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
            ExtensionPassiveScan extPassiveScan =  Control.getSingleton().getExtensionLoader().getExtension(ExtensionPassiveScan.class);
            policyScanner = (PolicyScanner) extPassiveScan.getPluginPassiveScanner(SCANNER_PLUGIN_ID);
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
        testRules.add(new CookieAttrRule());
        testRules.add(new HSTSRule());
        testRules.add(new EmailMatchingRule());
        testRules.add(new HTTPSRule());
        testRules.add(new DomainMatchingRule());
        testRules.add(new ExpectCTRule());
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

                            try {
                                loadRulesTest();
                                View.getSingleton().showMessageDialog("Test policy successfully loaded");
                            } catch (DuplicatePolicyException e) {
                                View.getSingleton().showMessageDialog("Test policy already loaded");
                            }
                        }
                    });
        }
        return menuPolicyLoader;
    }

}
