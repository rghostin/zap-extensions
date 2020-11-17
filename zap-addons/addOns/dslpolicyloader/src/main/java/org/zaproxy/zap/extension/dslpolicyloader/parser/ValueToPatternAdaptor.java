package org.zaproxy.zap.extension.dslpolicyloader.parser;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Convert literal values to their RE matching pattern
 */
public class ValueToPatternAdaptor {

    /**
     * Return a literal (escaped) re expression from the string
     * @param value : the value string
     * @return : escaped string to use as a regex literal
     */
    private String getReFromValue(String value) {
        return Pattern.quote(value);
    }

    /**
     * Return a re pattern that matches a given value
     * @param value : the value to match
     * @return : pattern matching the value
     */
    public Pattern getPatternFromValue(String value) {
        return Pattern.compile(getReFromValue(value));
    }

    /**
     * Return a re pattern that matches any value of the given list of values
     * @param values : the list of values
     * @return : pattern that matches any of the given values
     */
    public Pattern getPatternsFromValues(List<String> values) {
        String RE_LIAISON = "|";
        List<String> re_values_list = new ArrayList<>();
        for (String value : values) {
            re_values_list.add(getReFromValue(value));;
        }
        String re_all_values = String.join(RE_LIAISON, re_values_list);
        return Pattern.compile(re_all_values);
    }

}
