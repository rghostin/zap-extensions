package org.zaproxy.zap.extension.reportingproxy;

public class Pair<X, Y> {
    public final X first;
    public final Y second;

    public Pair(X x, Y y) {
        this.first = x;
        this.second = y;
    }

    public boolean equals(Object o) {

        if (o == null || o.getClass() != this.getClass()) { return false; }
        Pair<X, Y> that = (Pair<X, Y>) o;
        return (first == null ? that.first == null : first.equals(that.first))
                && (second == null ? that.second == null : second.equals(that.second));
    }

    public int hashCode() {
        return (first != null ? first.hashCode() : 0) + 31 * (second != null ? second.hashCode() : 0);
    }

}
