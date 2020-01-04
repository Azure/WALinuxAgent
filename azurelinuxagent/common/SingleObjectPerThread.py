from threading import Lock, currentThread


class _SingleObjectPerThreadMetaClass(type):
    """ A metaclass that creates a SingleObjectPerThread base class when called. """
    _instances = {}
    _lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            obj_name = "%s__%s" % (cls.__name__, currentThread().getName())  # Object Name = className__threadName
            if obj_name not in cls._instances:
                cls._instances[obj_name] = super(_SingleObjectPerThreadMetaClass, cls).__call__(*args, **kwargs)
        return cls._instances[obj_name]

    def clear(cls):
        obj_name = "%s__%s" % (cls.__name__, currentThread().getName())  # Object Name = className__threadName
        if obj_name in cls._instances:
            del cls._instances[obj_name]


class SingleObjectPerThread(_SingleObjectPerThreadMetaClass('SingleObjectPerThreadMetaClass', (object,), {})):
    # This base class calls the metaclass above to create the singleton per thread object. This class provides an
    # abstraction over how to invoke the Metaclass so just inheriting this class makes the child class a singleton
    # (As opposed to invoking the Metaclass separately for each derived classes)
    # More info here - https://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
    pass

