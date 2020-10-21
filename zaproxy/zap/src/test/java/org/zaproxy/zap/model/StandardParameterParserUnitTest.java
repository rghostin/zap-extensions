/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link StandardParameterParser}. */
public class StandardParameterParserUnitTest {

    private StandardParameterParser spp;

    @BeforeEach
    public void setUp() throws Exception {
        spp = new StandardParameterParser();
    }

    @Test
    public void defaultValues() {
        assertEquals(spp.getDefaultKeyValuePairSeparator(), "&");
        assertEquals(spp.getDefaultKeyValueSeparator(), "=");
    }

    @Test
    public void defaultParser() {
        assertEquals(spp.getKeyValuePairSeparators(), "&");
        assertEquals(spp.getKeyValueSeparators(), "=");
        assertEquals(spp.getStructuralParameters().size(), 0);

        @SuppressWarnings("deprecation")
        Map<String, String> res = spp.parse("a=b&b=c&d=f");
        assertEquals(res.size(), 3);
        assertEquals(res.get("a"), "b");
        assertEquals(res.get("b"), "c");
        assertEquals(res.get("d"), "f");

        List<NameValuePair> res2 = spp.parseParameters("a=b&b=c&d=f&d=g");
        assertEquals(res2.size(), 4);
        assertEquals(res2.get(0).getName(), "a");
        assertEquals(res2.get(0).getValue(), "b");
        assertEquals(res2.get(1).getName(), "b");
        assertEquals(res2.get(1).getValue(), "c");
        assertEquals(res2.get(2).getName(), "d");
        assertEquals(res2.get(2).getValue(), "f");
        assertEquals(res2.get(3).getName(), "d");
        assertEquals(res2.get(3).getValue(), "g");
    }

    @Test
    public void nonDefaultParser() {
        spp.setKeyValuePairSeparators(";");
        spp.setKeyValueSeparators(":=");
        List<String> sps = new ArrayList<>();
        sps.add("page");
        spp.setStructuralParameters(sps);
        @SuppressWarnings("deprecation")
        Map<String, String> res = spp.parse("a=b&c;b:c");
        List<NameValuePair> res2 = spp.parseParameters("a=b&c;b:c");

        assertEquals(spp.getKeyValuePairSeparators(), ";");
        assertEquals(spp.getKeyValueSeparators(), ":=");
        assertEquals(spp.getStructuralParameters().size(), 1);
        assertEquals(spp.getStructuralParameters().get(0), "page");

        assertEquals(res.size(), 2);
        assertEquals(res.get("a"), "b&c");
        assertEquals(res.get("b"), "c");

        assertEquals(res2.size(), 2);
        assertEquals(res2.get(0).getName(), "a");
        assertEquals(res2.get(0).getValue(), "b&c");
        assertEquals(res2.get(1).getName(), "b");
        assertEquals(res2.get(1).getValue(), "c");
    }

    @Test
    public void saveAndLoad() {
        spp.setKeyValuePairSeparators(";");
        spp.setKeyValueSeparators(":=");
        List<String> sps = new ArrayList<>();
        sps.add("page");
        spp.setStructuralParameters(sps);

        StandardParameterParser spp2 = new StandardParameterParser();
        spp2.init(spp.getConfig());

        @SuppressWarnings("deprecation")
        Map<String, String> res = spp2.parse("a=b&c;b:c");
        List<NameValuePair> res2 = spp2.parseParameters("a=b&c;b:c");

        assertEquals(spp2.getKeyValuePairSeparators(), ";");
        assertEquals(spp2.getKeyValueSeparators(), ":=");
        assertEquals(spp2.getStructuralParameters().size(), 1);
        assertEquals(spp2.getStructuralParameters().get(0), "page");

        assertEquals(res.size(), 2);
        assertEquals(res.get("a"), "b&c");
        assertEquals(res.get("b"), "c");
        assertEquals(res2.size(), 2);

        assertEquals(res2.get(0).getName(), "a");
        assertEquals(res2.get(0).getValue(), "b&c");
        assertEquals(res2.get(1).getName(), "b");
        assertEquals(res2.get(1).getValue(), "c");
    }

    /**
     * Gets the path of the URI's ancestor found at the given depth, taking into account any context
     * specific configuration (e.g. structural parameters). The depth could also be seen as the
     * number of path elements returned.
     *
     * <p>A few examples (uri, depth):
     *
     * <ul>
     *   <li>(<i>http://example.org/path/to/element</i>, 0) -> ""
     *   <li>(<i>http://example.org/path/to/element</i>, 1) -> "/path"
     *   <li>(<i>http://example.org/path/to/element</i>, 3) -> "/path/to/element"
     *   <li>(<i>http://example.org/path?page=12&data=123</i>, 2) -> "/path?page=12", if {@code
     *       page} is a structural parameter
     *   <li>(<i>http://example.org/path?page=12&data=123&type=1</i>, 3) -> "/path?page=12&type=1",
     *       if {@code page} and {@code type} are both structural parameter
     * </ul>
     *
     * @throws NullPointerException
     * @throws URIException if an error occurred while accessing the provided uri
     */
    @Test
    public void ancestorPath() throws Exception {
        // standard urls
        assertEquals(
                "", spp.getAncestorPath(new URI("http://example.org/path/to/element", true), 0));
        assertEquals(
                "/path",
                spp.getAncestorPath(new URI("http://example.org/path/to/element", true), 1));
        assertEquals(
                "/path/to",
                spp.getAncestorPath(new URI("http://example.org/path/to/element", true), 2));
        assertEquals(
                "/path/to/element",
                spp.getAncestorPath(new URI("http://example.org/path/to/element", true), 3));
        assertEquals(
                "/path",
                spp.getAncestorPath(new URI("http://example.org/path?page=12&data=123", true), 3));
        assertEquals(
                "/path",
                spp.getAncestorPath(
                        new URI("http://example.org/path?page=12&data=123&type=1", true), 3));

        // With structural params
        List<String> structuralParameters = new ArrayList<>();
        structuralParameters.add("page");
        structuralParameters.add("type");
        spp.setStructuralParameters(structuralParameters);
        assertEquals(
                "/path?page=12",
                spp.getAncestorPath(new URI("http://example.org/path?page=12&data=123", true), 3));
        assertEquals(
                "/path?page=12&type=1",
                spp.getAncestorPath(
                        new URI("http://example.org/path?page=12&data=123&type=1", true), 3));

        // with data driven nodes
        Context context = new Context(null, 0);
        Pattern p = Pattern.compile("http://example.org/(path/to/)(.+?)(/.*)");
        StructuralNodeModifier ddn =
                new StructuralNodeModifier(StructuralNodeModifier.Type.DataDrivenNode, p, "DDN");
        context.addDataDrivenNodes(ddn);
        spp.setContext(context);
        assertEquals(
                "/path/to/(.+?)",
                spp.getAncestorPath(new URI("http://example.org/path/to/ddn/aa", true), 3));
        assertEquals(
                "/path/to/(.+?)/aa",
                spp.getAncestorPath(new URI("http://example.org/path/to/ddn/aa", true), 4));
    }
}
