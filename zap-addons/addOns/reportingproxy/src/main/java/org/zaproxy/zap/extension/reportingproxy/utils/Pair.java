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

/**
 * Generic pair
 *
 * @param <X> : the first object type
 * @param <Y> : the second object type
 */
public class Pair<X, Y> {
    public final X first;
    public final Y second;

    public Pair(X x, Y y) {
        this.first = x;
        this.second = y;
    }

    @Override
    public boolean equals(Object o) {

        if (o == null) {
            return false;
        }
        if (!(o instanceof Pair)) {
            return false;
        }
        Pair<?, ?> that = (Pair<?, ?>) o;
        return (first == null ? that.first == null : first.equals(that.first))
                && (second == null ? that.second == null : second.equals(that.second));
    }

    @Override
    public int hashCode() {
        return (first != null ? first.hashCode() : 0)
                + 31 * (second != null ? second.hashCode() : 0);
    }
}
