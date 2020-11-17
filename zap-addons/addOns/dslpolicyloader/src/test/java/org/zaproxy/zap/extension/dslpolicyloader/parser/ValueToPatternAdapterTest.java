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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

class ValueToPatternAdapterTest {

    private List<String> getTestString() {
        return new ArrayList<>(
                Arrays.asList(
                        "test",
                        "test adapter",
                        "See \"what\" is reg ex",
                        "\"^max-age=(\\\\d+)(?:\\\\s*;\\\\s*includeSubDomains)?(?:\\\\s*;\\\\s*preload)?$\""));
    }

    @Test
    void getPatternFromValue() {
        List<String> testStrings = getTestString();

        for(String test : testStrings) {
            Pattern p = ValueToPatternAdapter.getPatternFromValue(test);
            assertEquals(p.toString(),"\\Q" + test+  "\\E");
        }
    }

    @Test
    void getPatternsFromValues() {
        List<String> testStrings = getTestString();
        List<String> res = new ArrayList<>();
        Pattern patterns = ValueToPatternAdapter.getPatternsFromValues(testStrings);

        String result = "";
        for(String test : testStrings) {
            String res_temp = "\\Q" + test+  "\\E";
            res.add(res_temp);
        }

        String re_all_values = String.join("|", res);

        assertEquals(re_all_values,patterns.toString());
    }

    @Test
    void getPatternsFromOneValues() {
        List<String> testStrings = new ArrayList<>(Arrays.asList("a"));
        List<String> res = new ArrayList<>();
        Pattern patterns = ValueToPatternAdapter.getPatternsFromValues(testStrings);

        String result = "";
        for(String test : testStrings) {
            String res_temp = "\\Q" + test+  "\\E";
            res.add(res_temp);
        }

        String re_all_values = String.join("|", res);

        assertEquals(re_all_values,patterns.toString());
    }

    @Test
    void getPatternsFromEmptyValues() {
        List<String> testStrings = new ArrayList<>();
        Pattern patterns = ValueToPatternAdapter.getPatternsFromValues(testStrings);

        System.out.println(patterns.toString());

        assertEquals("",patterns.toString());
    }
}
