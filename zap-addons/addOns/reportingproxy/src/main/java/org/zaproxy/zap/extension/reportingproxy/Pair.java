package org.zaproxy.zap.extension.reportingproxy;

public class Pair<X, Y> {
    public final X first;
    public final Y second;

    public Pair(X x, Y y) {
        this.first = x;
        this.second = y;
    }

    @Override
    public boolean equals(Object o) {

        if (o == null) { return false; }
        if (!(o instanceof Pair)) {
            return false;
        }
        Pair<?, ?> that = (Pair<?, ?>) o;
        return (first == null ? that.first == null : first.equals(that.first))
                && (second == null ? that.second == null : second.equals(that.second));
    }

    @Override
    public int hashCode() {
        return (first != null ? first.hashCode() : 0) + 31 * (second != null ? second.hashCode() : 0);
    }

}
