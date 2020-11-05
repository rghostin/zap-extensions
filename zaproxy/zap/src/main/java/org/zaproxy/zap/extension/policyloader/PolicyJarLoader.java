package org.zaproxy.zap.extension.policyloader;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class PolicyJarLoader {
    private String policyName;
    private Set<Rule> rules = new HashSet<>();

    public PolicyJarLoader(String pathToJar) throws ClassNotFoundException, InstantiationException, IllegalAccessException, IOException {
        policyName = extractPolicyName(pathToJar);
        loadPolicyJar(pathToJar);
    }

    static private String extractPolicyName(String pathToJar) {
        // todo fix
        return pathToJar.substring(pathToJar.lastIndexOf(File.separator)+1);
    }

    public String getPolicyName() {
        return policyName;
    }

    public Set<Rule> getRules() {
        return rules;
    }

    private void loadPolicyJar(String pathToJar) throws IOException, ClassNotFoundException, IllegalAccessException, InstantiationException {
        JarFile jarFile = new JarFile(pathToJar);
        URL[] urls = { new URL("jar:file:" + pathToJar+"!/") };
        URLClassLoader cl = URLClassLoader.newInstance(urls);

        Enumeration<JarEntry> entries = jarFile.entries();
        while (entries.hasMoreElements()) {
            JarEntry jentry = entries.nextElement();
            if(jentry.isDirectory() || !jentry.getName().endsWith(".class")){
                continue;
            }
            // get name of jar entry, strip the .class and convert to java path
            String className = jentry.getName();
            className = className.substring(0,jentry.getName().length()-6).replace('/', '.');

            Class<?> pluginRuleClass_ = cl.loadClass(className);
            Class<? extends Rule> pluginRuleClass = pluginRuleClass_.asSubclass(Rule.class);
            Rule pluginRule = pluginRuleClass.newInstance();
            rules.add(pluginRule);
        }
    }
}
