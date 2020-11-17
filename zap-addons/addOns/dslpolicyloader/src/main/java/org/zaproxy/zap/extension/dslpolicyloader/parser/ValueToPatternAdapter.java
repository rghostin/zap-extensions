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
package org.zaproxy.zap.extension.dslpolicyloader.parser;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** Convert literal values to their RE matching pattern */
public class ValueToPatternAdapter {

    /**
     * Return a literal (escaped) re expression from the string
     *
     * @param value : the value string
     * @return : escaped string to use as a regex literal
     */
    private static String getReFromValue(String value) {
        return Pattern.quote(value);
    }

    /**
     * Return a re pattern that matches a given value
     *
     * @param value : the value to match
     * @return : pattern matching the value
     */
    public static Pattern getPatternFromValue(String value) {
        return Pattern.compile(getReFromValue(value));
    }

    /**
     * Return a re pattern that matches any value of the given list of values
     *
     * @param values : the list of values
     * @return : pattern that matches any of the given values
     */
    public static Pattern getPatternsFromValues(List<String> values) {
        String RE_LIAISON = "|";
        List<String> re_values_list = new ArrayList<>();
        for (String value : values) {
            re_values_list.add(getReFromValue(value));
            ;
        }
        String re_all_values = String.join(RE_LIAISON, re_values_list);
        return Pattern.compile(re_all_values);
    }
}
