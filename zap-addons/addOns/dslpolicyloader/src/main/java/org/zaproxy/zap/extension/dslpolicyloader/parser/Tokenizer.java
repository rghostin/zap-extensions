package org.zaproxy.zap.extension.dslpolicyloader.parser;

import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Tokenizer implements Iterable<String> {
    private static final String RE_SIMPLE_STATEMENT =
            "\\s*(request|response)\\.(header|body)\\.(?:(re=\\\".*?\\\")|(value=\\\".*?\\\")|(values=\\[.*?\\]))\\s*";
    private static final String RE_LIAISON = "\\s*(and|or|not|\\(|\\))\\s*";
    private static final String RE_TOKEN = "("+RE_SIMPLE_STATEMENT+")|("+RE_LIAISON+")";
    private static final Pattern PATTERN_TOKEN = Pattern.compile(RE_TOKEN);

    private Matcher matcher;
    private String composedStatement;
    private int lastPos;

    @Override
    public Iterator<String> iterator() {
        return new TokenIterator(this);
    }

    private class TokenIterator implements Iterator<String> {
        TokenIterator(Tokenizer tokenizer) {}

        @Override
        public boolean hasNext() { return matcher.find(); }

        @Override
        public String next() {return getNextToken();}
    }

    public Tokenizer(String composedStatement) {
        this.composedStatement = composedStatement;
        this.lastPos = 0;
        this.matcher = PATTERN_TOKEN.matcher(composedStatement);
    }

    private String getNextToken() {
        if (matcher.find(lastPos)) {
            lastPos = matcher.end();
            return matcher.group().trim();
        } else {
            return null;
        }
    }




    public static void main(String[] args) { // todo remove
        String composedStatement = "(request.header.re=\"test\" and response.body.value=\"test2\") or request.header.values=[\"ada\",\"wfww\"]";

//        String token;
//        Tokenizer tokenizer = new Tokenizer(composedStatement);
//        while ( (token = tokenizer.getNextToken()) != null) {
//            System.out.println(token);
//        }

        for (String token : new Tokenizer(composedStatement)) {
            System.out.println(token);
        }

//        Tokenizer tokenizer = new Tokenizer(composedStatement);
//        Iterator<String> tokenIterator = tokenizer.iterator();
//        while (tokenIterator.hasNext()) {
//            System.out.println(tokenIterator.next());
//        }
    }
}
