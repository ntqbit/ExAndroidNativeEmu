from androidemu.java.jvm_id_counter import next_field_id


class JavaFieldDef:
    def __init__(self, name, signature, is_static=False, static_value=None, ignore=False):
        self.jvm_id = next_field_id()
        self.name = name
        self.signature = signature
        self.is_static = is_static
        self.static_value = static_value
        self.ignore = ignore

        if self.is_static and self.static_value is None:
            raise ValueError("Static value may not be None for a static field.")
