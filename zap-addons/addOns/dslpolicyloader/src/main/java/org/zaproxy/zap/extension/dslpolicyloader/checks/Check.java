package org.zaproxy.zap.extension.dslpolicyloader.checks;

import org.parosproxy.paros.network.HttpMessage;

import javax.print.DocFlavor;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class Check implements Predicate<HttpMessage> {
    Pattern pattern;

    abstract String getFieldOfOperation(HttpMessage msg);


    public Check(Pattern pattern) {
        this.pattern = pattern;
    }

    @Override
    public boolean test(HttpMessage msg) {
        String field = getFieldOfOperation(msg);
        Matcher matcher = pattern.matcher(field);
        return  matcher.find();
    }
}
