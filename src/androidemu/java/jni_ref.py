
class jobject:
    def __init__(self, value=None):
        self.value = value

    def __repr__(self):
        return f'jobject<{repr(self.value)}>'


class jclass(jobject):

    def __init__(self, value=None):
        super().__init__(value)

    def __repr__(self):
        return f'jclass<{repr(self.value)}>'
