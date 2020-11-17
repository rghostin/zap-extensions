package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.*;

import java.util.*;
import java.util.function.Predicate;

/**
 * Parses a composed statement into a Predicate\\<HttpMessage\\>
 *  A composed statement is defined by one or multiple simple statements joined by operators
 *  A simple statement is defined by {request|response}.{body|header}|{re="" | value="" | values=["","",..]}
 */
@SuppressWarnings("unchecked")
public class StatementParser {
    private Tokenizer tokenizer;

    /**
     * Load a composed statement into the parser
     * A composed statement
     * @param statement : The composed statement
     */
    public StatementParser(String statement) {
        tokenizer = new Tokenizer(statement);
    }

    /**
     * Adapted Dijkstra's Shunting yard algorithm
     * Tranforms infix to postfix (Polish Reverse Notation - PRN) queue of tokens
     * @return postfix queue of tokens
     */
    private Queue<Token> infixToPostfix() {
        Stack<Token> operatorStack = new Stack<>();
        Queue<Token> outputQueue = new LinkedList<>();

        for (Token token : tokenizer.getAllTokens()) {
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
                    HttpPredicateOperator prevOperator = (HttpPredicateOperator) operatorStack.peek().getTokenObj();
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
     * @param outputQueue : Queue containing tokens ordered in a postfix order (Polish Reverse Notation)
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
     * @return the predicate representing the statement
     */
    public Predicate<HttpMessage> parse() {
        Queue<Token> postfixTokens= infixToPostfix();
        return postfixEvaluate(postfixTokens);
    }


    public static void main(String[] args) { // todo remove
        String composedStatement = "request.header.re=\"test\" or   response.body.value=\"test2\" and ( request.header.values=[\"ada\",\"wfww\"] or not response.body.value=\"test4\")";
        StatementParser sttmtParser = new StatementParser(composedStatement);
        Predicate<HttpMessage> predicate = sttmtParser.parse();
        System.out.println(predicate);
    }
}
