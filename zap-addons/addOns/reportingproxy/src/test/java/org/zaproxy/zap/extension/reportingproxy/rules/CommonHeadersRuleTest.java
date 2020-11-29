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
package org.zaproxy.zap.extension.reportingproxy.rules;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.reportingproxy.Violation;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CommonHeadersRuleTest {

        private CommonHeadersRule commonHeadersRule;
        private HttpMessage httpRespMsg1;
        private HttpMessage httpRespMsg2;
        private HttpMessage httpRespMsg3;

        @BeforeEach
        void setup() {
            commonHeadersRule = new CommonHeadersRule();
            HttpHeaderField field1_1 = new HttpHeaderField("Accept", "text/html");
            HttpHeaderField field1_2 = new HttpHeaderField("Accept-Charset", "utf-8");
            HttpHeaderField field1_3 = new HttpHeaderField("Accept-Language", "en-US");
            HttpHeaderField field1_4 = new HttpHeaderField("Cookie", "sessionId=abc123");
            HttpHeaderField field2_1 = new HttpHeaderField("Accept", "application/xml");
            HttpHeaderField field2_2 = new HttpHeaderField("Accept-Charset", "GBK");
            HttpHeaderField field2_3 = new HttpHeaderField("Accept-Language", "zh;en-US");


            List<HttpHeaderField> listForMsg1 = new ArrayList<>();
            List<HttpHeaderField> listForMsg2 = new ArrayList<>();
            List<HttpHeaderField> listForMsg3 = new ArrayList<>();

            listForMsg1.add(field1_1);
            listForMsg1.add(field1_2);
            listForMsg1.add(field1_3);

            listForMsg2.addAll(listForMsg1);
            listForMsg2.add(field1_4);

            listForMsg3.add(field2_1);
            listForMsg3.add(field2_2);
            listForMsg3.add(field2_3);

            // For creating of first HttpMessage
            httpRespMsg1 = createHttpRespMsg(listForMsg1);
            // For creating of second HttpMessage
            httpRespMsg2 = createHttpRespMsg(listForMsg2);
            // For creating of third HttpMessage
            httpRespMsg3 = createHttpRespMsg(listForMsg3);
        }

        @Test
        void getName() {
            assertEquals("Common_Headers_Rule", commonHeadersRule.getName());
        }

        @Test
        void getDescription() {
            assertEquals(
                    "The HTTP response message does not contain common response header " +
                    "present in previous requests."
                    , commonHeadersRule.getDescription());
        }

        @Test
        void updateBufferWith() {
            assertNull(commonHeadersRule.checkViolation(httpRespMsg2));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            List<HttpResponseHeader> container =
            commonHeadersRule.getHttpResponseHeaderContainer();
            assertTrue(container.contains(httpRespMsg2.getResponseHeader()));
            commonHeadersRule.checkViolation(httpRespMsg1);
            assertFalse(container.contains(httpRespMsg2.getResponseHeader()));
        }

        @Test
        void isViolatedTrue() {
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));

            Violation v = commonHeadersRule.checkViolation(httpRespMsg3);
            assertNull(v);
        }

        @Test
        void isViolatedFalse() {
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg2));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));

            assertNull(commonHeadersRule.checkViolation(httpRespMsg1));
        }

        private HttpMessage createHttpRespMsg(List<HttpHeaderField> headers) {
            try {
                HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
                for (HttpHeaderField header : headers) {
                    msg.getResponseHeader().setHeader(header.getName(), header.getValue());
                }
                return msg;
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

}
