from threading import Lock, currentThread


class _SingletonPerThreadMetaClass(type):
    """ A metaclass that creates a SingletonPerThread base class when called. """
    _instances = {}
    _lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            obj_name = "%s__%s" % (cls.__name__, currentThread().getName())  # Object Name = className__threadName
            if obj_name not in cls._instances:
                cls._instances[obj_name] = super(_SingletonPerThreadMetaClass, cls).__call__(*args, **kwargs)
            return cls._instances[obj_name]


class SingletonPerThread(_SingletonPerThreadMetaClass('SingleObjectPerThreadMetaClass', (object,), {})): # pylint: disable=R0903
    # This base class calls the metaclass above to create the singleton per thread object. This class provides an
    # abstraction over how to invoke the Metaclass so just inheriting this class makes the
    # child class a singleton per thread (As opposed to invoking the Metaclass separately for each derived classes)
    # More info here - https://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
    #
    # Usage:
    # Inheriting this class will create a Singleton per thread for that class
    # To delete the cached object of a class, call DerivedClassName.clear() to delete the object per thread
    # Note: If the thread dies and is recreated with the same thread name, the existing object would be reused
    # and no new object for the derived class would be created unless DerivedClassName.clear() is called explicitly to
    # delete the cache
    pass

