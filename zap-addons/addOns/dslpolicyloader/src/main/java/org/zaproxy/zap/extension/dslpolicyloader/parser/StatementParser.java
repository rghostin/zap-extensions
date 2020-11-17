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

import java.util.*;
import java.util.function.Predicate;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.exceptions.SyntaxErrorException;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.*;

/**
 * Parses a composed statement into a Predicate\\<HttpMessage\\> A composed statement is defined by
 * one or multiple simple statements joined by operators A simple statement is defined by
 * {request|response}.{body|header}|{re="" | value="" | values=["","",..]}
 */
@SuppressWarnings("unchecked")
public class StatementParser {
    private Tokenizer tokenizer;

    /**
     * Load a composed statement into the parser A composed statement
     *
     * @param statement : The composed statement
     */
    public StatementParser(String statement) {
        tokenizer = new Tokenizer(statement);
    }

    /**
     * Adapted Dijkstra's Shunting yard algorithm Tranforms infix to postfix (Polish Reverse
     * Notation - PRN) queue of tokens
     *
     * @param tokens : A list of tokens in infix order
     * @return postfix queue of tokens
     */
    private Queue<Token> infixToPostfix(List<Token> tokens) {
        Stack<Token> operatorStack = new Stack<>();
        Queue<Token> outputQueue = new LinkedList<>();

        for (Token token : tokens) {
            if (token.isOpenParenthesis()) {
                operatorStack.push(token);
            } else if (token.isClosedParenthesis()) {
                while (!operatorStack.peek().isOpenParenthesis()) {
                    outputQueue.add(operatorStack.pop());
                }
                operatorStack.pop(); // discard open parenthesis
            } else if (token.isOperator()) {
                HttpPredicateOperator operator = (HttpPredicateOperator) token.getTokenObj();

                while (!operatorStack.empty() && !operatorStack.peek().isOpenParenthesis()) {
                    HttpPredicateOperator prevOperator =
                            (HttpPredicateOperator) operatorStack.peek().getTokenObj();
                    if (!prevOperator.hasHigherPrecedenceOver(operator)) {
                        break;
                    }
                    outputQueue.add(operatorStack.pop());
                }
                operatorStack.push(token);
            } else if (token.isSimplePredicate()) {
                outputQueue.add(token);
            } else {
                throw new IllegalStateException("Logic error");
            }
        }

        while (!operatorStack.empty()) {
            outputQueue.add(operatorStack.pop());
        }
        return outputQueue;
    }

    /**
     * Evaluates postfix notation to a single Predicate object
     *
     * @param outputQueue : Queue containing tokens ordered in a postfix order (Polish Reverse
     *     Notation)
     * @return Predicate representing the expression
     */
    private Predicate<HttpMessage> postfixEvaluate(Queue<Token> outputQueue) {
        Stack<Predicate<HttpMessage>> operandsStack = new Stack<>();

        for (Token t : outputQueue) {
            if (t.isSimplePredicate()) {
                operandsStack.push((Predicate<HttpMessage>) t.getTokenObj());
            } else if (t.isOperator()) {
                HttpPredicateOperator operator = (HttpPredicateOperator) t.getTokenObj();
                List<Predicate<HttpMessage>> operands = new ArrayList<>();
                for (int i = 0; i < operator.getArity(); i++) {
                    operands.add(operandsStack.pop());
                }
                Predicate<HttpMessage> predicate = operator.operate(operands);
                operandsStack.push(predicate);
            } else {
                throw new IllegalStateException("Unsupported token type");
            }
        }
        assert operandsStack.size() == 1;
        return operandsStack.pop();
    }

    /**
     * Parse the loaded composed statement to a predicate
     *
     * @return the predicate representing the statement
     */
    public Predicate<HttpMessage> parse() throws SyntaxErrorException {
        List<Token> tokens = tokenizer.getAllTokens();
        Queue<Token> postfixTokens = infixToPostfix(tokens);
        return postfixEvaluate(postfixTokens);
    }
}
