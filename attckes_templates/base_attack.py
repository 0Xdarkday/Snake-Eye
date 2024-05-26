class BaseAttack:
    def __init__(self, reporter):
        self.reporter = reporter

    def detect(self, packet):
        raise NotImplementedError("Subclasses should implement this method")


