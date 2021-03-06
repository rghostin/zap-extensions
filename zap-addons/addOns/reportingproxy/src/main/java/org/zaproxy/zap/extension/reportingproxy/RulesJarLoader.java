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

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Responsible of loading a JAR file containing policies */
public class RulesJarLoader {
    Set<Rule> rules = new HashSet<>();

    /** @return a set of the loaded rules */
    public Set<Rule> getRules() {
        return rules;
    }

    /**
     * Load the jar file's rules as a policy
     *
     * @param pathToJar : path to jar file on the filesystem
     * @throws ClassNotFoundException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws IOException
     */
    public RulesJarLoader(String pathToJar)
            throws ClassNotFoundException, InstantiationException, IllegalAccessException,
                    IOException {
        loadJar(pathToJar);
    }

    /**
     * Loads the jar file containing rules
     *
     * @param pathToJar
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws IllegalAccessException
     * @throws InstantiationException
     */
    private void loadJar(String pathToJar)
            throws IOException, ClassNotFoundException, IllegalAccessException,
                    InstantiationException {
        JarFile jarFile = new JarFile(pathToJar);
        URL[] urls = {new URL("jar:file:" + pathToJar + "!/")};
        URLClassLoader cl = URLClassLoader.newInstance(urls, getClass().getClassLoader());

        Enumeration<JarEntry> entries = jarFile.entries();
        while (entries.hasMoreElements()) {
            JarEntry jentry = entries.nextElement();
            if (jentry.isDirectory() || !jentry.getName().endsWith(".class")) {
                continue;
            }
            // get name of jar entry, strip the .class and convert to java path
            String className = jentry.getName();
            className = className.substring(0, jentry.getName().length() - 6).replace('/', '.');

            Class<?> pluginRuleClass_ = cl.loadClass(className);
            Class<? extends Rule> pluginRuleClass = pluginRuleClass_.asSubclass(Rule.class);
            Rule pluginRule = pluginRuleClass.newInstance();
            rules.add(pluginRule);
        }
    }
}
