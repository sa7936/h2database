package org.h2.value;

import org.h2.util.StringUtils;

/**
 * Implementation of the PASSWORD data type.
 */
public final class ValuePassword extends ValueStringBase {

    private ValuePassword(String value) {
        super(value);
    }

    @Override
    public int getValueType() {
        return PASSWORD;
    }

    @Override
    public StringBuilder getSQL(StringBuilder builder, int sqlFlags) {
        return StringUtils.quoteStringSQL(builder, value);
    }

    /**
     * Get a PASSWORD value for the given string. This is just storing the
     * string passed in, no hashing done yet.
     *
     * @param s the stored password representation
     * @return the value
     */
    public static ValuePassword get(String s) {
        return new ValuePassword(StringUtils.cache(s));
    }
}
