class jobject:
    def __init__(self, value=None):
        self.value = value

    def __repr__(self):
        return f"jobject<{repr(self.value)}>"


class jclass(jobject):
    def __init__(self, value=None):
        if value is None:
            raise ValueError('jclass cannot be None')

        super().__init__(value)

    def __repr__(self):
        return f"jclass<{repr(self.value)}>"


class jthrowable(jobject):
    def __init__(self, value=None):
        if value is None:
            raise ValueError('jthrowable cannot be None')

        super().__init__(value)

    def __repr__(self):
        return f'jthrowable<{repr(self.value)}>'
