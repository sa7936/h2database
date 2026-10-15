/*
 * Copyright 2004-2026 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 */
package org.h2.expression.function;

import org.h2.engine.SessionLocal;
import org.h2.expression.Expression;
import org.h2.message.DbException;
import org.h2.value.TypeInfo;
import org.h2.value.Value;
import org.h2.value.ValueBoolean;
import org.h2.value.ValuePassword;

/**
 * PASSWORD_VERIFY(stored credential, candidate plaintext).
 */
public final class PasswordVerifyFunction extends Function2 {

    public PasswordVerifyFunction(Expression stored, Expression candidate) {
        super(stored, candidate);
    }

    @Override
    protected Value getValue(SessionLocal session, Value stored, Value candidate) {
        if (!(stored instanceof ValuePassword)) {
            throw DbException.getInvalidValueException("PASSWORD_VERIFY stored value", "PASSWORD required");
        }
        return ValueBoolean.get(((ValuePassword) stored).verify(candidate.getString()));
    }

    @Override
    public Expression optimize(SessionLocal session) {
        left = left.optimize(session);
        right = right.optimize(session);
        type = TypeInfo.TYPE_BOOLEAN;
        return this;
    }

    @Override
    public String getName() {
        return "PASSWORD_VERIFY";
    }
}
