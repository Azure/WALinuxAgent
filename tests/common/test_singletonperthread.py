import uuid
from multiprocessing import Queue
from threading import Thread, currentThread

from azurelinuxagent.common.singletonperthread import SingletonPerThread
from tests.tools import AgentTestCase, clear_singleton_instances


class TestClassToTestSingletonPerThread(SingletonPerThread):
    """
    Since these tests deal with testing in a multithreaded environment,
    we employ the use of multiprocessing.Queue() to ensure that the data is consistent.

     This test class uses a uuid to identify an object instead of directly using object reference because
    Queue.get() returns a different object reference than what is put in it even though the object is same
    (which is verified using uuid in this test class)

    Eg:

        obj1 = WireClient("obj1")
        obj1
        <__main__.WireClient object at 0x7f5e78476198>
        q = Queue()
        q.put(obj1)
        test1 = q.get()
        test1
        <__main__.WireClient object at 0x7f5e78430630>

        test1.endpoint == obj1.endpoint
        True
    """

    def __init__(self):
        # Set the name of the object to the current thread name
        self.name = currentThread().getName()
        # Unique identifier for a class object
        self.uuid = str(uuid.uuid4())


class TestSingletonPerThread(AgentTestCase):

    THREAD_NAME_1 = 'thread-1'
    THREAD_NAME_2 = 'thread-2'

    def setUp(self):
        super(TestSingletonPerThread, self).setUp()
        # In a multi-threaded environment, exceptions thrown in the child thread will not be propagated to the parent
        # thread. In order to achieve that, adding all exceptions to a Queue and then checking that in parent thread.
        self.errors = Queue()
        clear_singleton_instances(TestClassToTestSingletonPerThread)

    def _setup_multithread_and_execute(self, func1, args1, func2, args2, t1_name=None, t2_name=None):

        t1 = Thread(target=func1, args=args1)
        t2 = Thread(target=func2, args=args2)
        t1.setName(t1_name if t1_name else self.THREAD_NAME_1)
        t2.setName(t2_name if t2_name else self.THREAD_NAME_2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        errs = []
        while not self.errors.empty():
            errs.append(self.errors.get())
        if len(errs) > 0:
            raise Exception("Errors: %s" % ' , '.join(errs))

    @staticmethod
    def _get_test_class_instance(q, err):
        try:
            obj = TestClassToTestSingletonPerThread()
            q.put(obj)
        except Exception as e:
            err.put(str(e))

    def _parse_instances_and_return_thread_objects(self, instances, t1_name=None, t2_name=None):
        obj1, obj2 = instances.get(), instances.get()

        def check_obj(name):
            if obj1.name == name:
                return obj1
            elif obj2.name == name:
                return obj2
            else:
                return None

        t1_object = check_obj(t1_name if t1_name else self.THREAD_NAME_1)
        t2_object = check_obj(t2_name if t2_name else self.THREAD_NAME_2)

        return t1_object, t2_object

    def test_it_should_have_only_one_instance_for_same_thread(self):
        obj1 = TestClassToTestSingletonPerThread()
        obj2 = TestClassToTestSingletonPerThread()

        self.assertEqual(obj1.uuid, obj2.uuid)

    def test_it_should_have_multiple_instances_for_multiple_threads(self):
        instances = Queue()
        self._setup_multithread_and_execute(func1=self._get_test_class_instance,
                                            args1=(instances, self.errors),
                                            func2=self._get_test_class_instance,
                                            args2=(instances, self.errors))

        self.assertEqual(2, instances.qsize())  # Assert that there are 2 objects in the queue
        obj1, obj2 = instances.get(), instances.get()
        self.assertNotEqual(obj1.uuid, obj2.uuid)

    def test_it_should_return_existing_instance_for_new_thread_with_same_name(self):

        instances = Queue()
        self._setup_multithread_and_execute(func1=self._get_test_class_instance,
                                            args1=(instances, self.errors),
                                            func2=self._get_test_class_instance,
                                            args2=(instances, self.errors))

        t1_obj, t2_obj = self._parse_instances_and_return_thread_objects(instances)

        new_instances = Queue()
        # The 2nd call is to get new objects with the same thread name to verify if the objects are same
        self._setup_multithread_and_execute(func1=self._get_test_class_instance,
                                            args1=(new_instances, self.errors),
                                            func2=self._get_test_class_instance,
                                            args2=(new_instances, self.errors))

        new_t1_obj, new_t2_obj = self._parse_instances_and_return_thread_objects(new_instances)

        self.assertEqual(t1_obj.name, new_t1_obj.name)
        self.assertEqual(t1_obj.uuid, new_t1_obj.uuid)
        self.assertEqual(t2_obj.name, new_t2_obj.name)
        self.assertEqual(t2_obj.uuid, new_t2_obj.uuid)

    def test_singleton_object_should_match_thread_name(self):

        instances = Queue()
        t1_name = str(uuid.uuid4())
        t2_name = str(uuid.uuid4())

        test_class_obj_name = lambda t_name: "%s__%s" % (TestClassToTestSingletonPerThread.__name__, t_name)

        self._setup_multithread_and_execute(func1=self._get_test_class_instance,
                                            args1=(instances, self.errors),
                                            func2=self._get_test_class_instance,
                                            args2=(instances, self.errors),
                                            t1_name=t1_name,
                                            t2_name=t2_name)

        singleton_instances = TestClassToTestSingletonPerThread._instances  # pylint: disable=protected-access,no-member

        # Assert instance names are consistent with the thread names
        self.assertIn(test_class_obj_name(t1_name), singleton_instances)
        self.assertIn(test_class_obj_name(t2_name), singleton_instances)

        # Assert that the objects match their respective threads
        # This function matches objects with their thread names and returns the respective object or None if not found
        t1_obj, t2_obj = self._parse_instances_and_return_thread_objects(instances, t1_name, t2_name)
        # Ensure that objects for both the threads were found
        self.assertIsNotNone(t1_obj)
        self.assertIsNotNone(t2_obj)
        # Ensure that the objects match with their respective thread objects
        self.assertEqual(singleton_instances[test_class_obj_name(t1_name)].uuid, t1_obj.uuid)
        self.assertEqual(singleton_instances[test_class_obj_name(t2_name)].uuid, t2_obj.uuid)

