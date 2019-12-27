# works in Python 2 & 3
from threading import Lock


class _Singleton(type):
    """ A metaclass that creates a Singleton base class when called. """
    _instances = {}
    _lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                cls._instances[cls] = super(_Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

    def clear(cls):
        try:
            del cls._instances[cls]
        except Exception:
            pass


class Singleton(_Singleton('SingletonMeta', (object,), {})):
    # This base class calls the metaclass above to create the singleton object. This class provides an
    # abstraction over how to invoke the Metaclass so just inheriting this class makes the child class a singleton
    # (As opposed to invoking the Metaclass separately for each derived classes)
    # More info here - https://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
    pass
