import itertools

from androidemu.const.emu_const import JMETHOD_ID_BASE, JFIELD_ID_BASE

NEXT_JVM_CLASS_ID = itertools.count(start=1)
NEXT_JVM_METHOD_ID = itertools.count(start=JMETHOD_ID_BASE, step=4)
NEXT_JVM_FIELD_ID = itertools.count(start=JFIELD_ID_BASE, step=4)


def next_class_id():
    return next(NEXT_JVM_CLASS_ID)


def next_method_id():
    return next(NEXT_JVM_METHOD_ID)


def next_field_id():
    return next(NEXT_JVM_FIELD_ID)

