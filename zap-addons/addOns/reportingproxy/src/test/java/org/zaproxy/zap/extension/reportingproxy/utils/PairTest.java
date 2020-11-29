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
package org.zaproxy.zap.extension.reportingproxy.utils;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class PairTest {

    @Test
    public void testEquals_Symmetric() {
        Pair<String, String> x = new Pair<>("lol","gg");  // equals and hashCode check name field value
        Pair<String, String> y = new Pair<>("lol","gg");  // equals and hashCode check name field value
        assertTrue(x.equals(y) && y.equals(x));
        assertTrue(x.hashCode() == y.hashCode());

        Pair<Integer, Integer> a = new Pair<>(1,2);  // equals and hashCode check name field value
        Pair<Integer, Integer> b = new Pair<>(3,2);  // equals and hashCode check name field value
        assertFalse(a.equals(b) || b.equals(a));
        assertFalse(a.hashCode() == b.hashCode());

        assertFalse(x.equals(a) || y.equals(b));

        assertFalse(x.equals(null));
        assertFalse(x.equals("LOL"));
    }
}
