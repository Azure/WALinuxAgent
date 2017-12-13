from datetime import datetime, timedelta

ERROR_STATE_DELTA = timedelta(minutes=15)

class ErrorState(object):
    def __init__(self, min_timedelta):
        self.min_timedelta = min_timedelta

        self.count = 0;
        self.timestamp = None

    def incr(self):
        if self.count == 0:
            self.timestamp = datetime.utcnow()

        self.count += 1

    def reset(self):
        self.count = 0
        self.timestamp = None

    def is_triggered(self):
        if self.timestamp is None:
            return False

        delta = datetime.utcnow() - self.timestamp
        if delta >= self.min_timedelta:
            return True

        return False
