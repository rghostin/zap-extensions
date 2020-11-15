package org.zaproxy.zap.extension.dslpolicyloader.parser;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Tokenizer {
    private static final String RE_SIMPLE_STATEMENT =
            "(request|response)\\.(header|body)\\.(?:(re=\\\".*?\\\")|(value=\\\".*?\\\")|(values=\\[.*?\\]))";
    private static final String RE_LIAISON = "\\s*(and|or|not|\\(|\\))\\s*";
    private static final String RE_TOKEN = "("+RE_SIMPLE_STATEMENT+")|("+RE_LIAISON+")";
    private static final Pattern PATTERN_TOKEN = Pattern.compile(RE_TOKEN);

    private Matcher matcher;
    private String composedStatement;
    private int lastPos;

    public Tokenizer(String composedStatement) {
        this.composedStatement = composedStatement;
        this.lastPos = 0;
        this.matcher = PATTERN_TOKEN.matcher(composedStatement);
    }

    public String getNextToken() {
        if (matcher.find(lastPos)) {
            System.out.println(matcher.start() + ":" + matcher.end());
            lastPos = matcher.end();
            return matcher.group();
        } else {
            return null;
        }
    }

    public static void main(String[] args) {
        String composedStatement = "(request.header.re=\"test\" and response.body.value=\"test2\") or request.header.values=[\"ada\",\"wfww\"]";

        String token;
        Tokenizer tokenizer = new Tokenizer(composedStatement);
        while ( (token = tokenizer.getNextToken()) != null) {
            System.out.println(token);
        }
    }
}
