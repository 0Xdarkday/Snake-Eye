class BaseAttack:
    def __init__(self, reporter):
        self.reporter = reporter

    def detect(self, packet):
        raise NotImplementedError("This method should be overridden by subclasses")
