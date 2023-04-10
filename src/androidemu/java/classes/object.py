from androidemu.java import JavaClassDef


class Object(metaclass=JavaClassDef, jvm_name="java/lang/Object"):
    def __init__(self):
        pass

    def __repr__(self):
        return "Object()"
