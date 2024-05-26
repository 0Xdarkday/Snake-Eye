class BaseAttack:
    def __init__(self, reporter):
        self.reporter = reporter

    def detect(self, packet):
        """
        Detects an attack. Should be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses should implement this method")
