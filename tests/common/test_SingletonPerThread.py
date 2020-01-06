import uuid
from multiprocessing import Queue
from threading import Thread

from azurelinuxagent.common.SingletonPerThread import SingletonPerThread
from tests.tools import AgentTestCase


class TestSingletonPerThreadClass(SingletonPerThread):

    def __init__(self, name=None):
        self.name = name
        # Unique identifier for a class object
        self.uuid = str(uuid.uuid4())


class TestSingletonPerThread(AgentTestCase):

    THREAD_NAME_1 = 'thread-1'
    THREAD_NAME_2 = 'thread-2'

    def setUp(self):
        super(TestSingletonPerThread, self).setUp()
        self.errors = Queue()
        TestSingletonPerThreadClass.clear()

    def _setup_mutithread_and_execute(self, func1, args1, func2, args2):

        t1 = Thread(target=func1, args=args1)
        t2 = Thread(target=func2, args=args2)
        t1.setName(self.THREAD_NAME_1)
        t2.setName(self.THREAD_NAME_2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        errs = []
        while not self.errors.empty():
            errs.append(self.errors.get())
        if len(errs) > 0:
            raise Exception("Unable to fetch protocol_util. Errors: %s" % ' , '.join(errs))

    @staticmethod
    def _get_test_class_instance(q, err, name=None):
        try:
            obj = TestSingletonPerThreadClass(name)
            q.put(obj)
        except Exception as e:
            err.put(str(e))

    def _parse_output_and_return_thread_objects(self, queue_output):
        obj1, obj2 = queue_output.get(), queue_output.get()

        t1_object = obj1 if obj1.name == self.THREAD_NAME_1 else obj2
        t2_object = obj1 if obj1.name == self.THREAD_NAME_2 else obj2

        return t1_object, t2_object

    def test_it_should_have_only_one_instance_for_same_thread(self):
        obj1 = TestSingletonPerThreadClass()
        obj2 = TestSingletonPerThreadClass()

        self.assertEqual(obj1.uuid, obj2.uuid)

    def test_it_should_have_multiple_instances_for_multiple_threads(self):
        output = Queue()
        self._setup_mutithread_and_execute(func1=self._get_test_class_instance,
                                           args1=(output, self.errors),
                                           func2=self._get_test_class_instance,
                                           args2=(output, self.errors))

        self.assertEqual(2, output.qsize())  # Assert that there are 2 objects in the queue
        obj1, obj2 = output.get(), output.get()
        self.assertNotEqual(obj1.uuid, obj2.uuid)

    def test_it_should_remove_instance_for_calling_thread_on_clear(self):

        def get_and_clear_test_class_instance(q, err):
            try:
                q.put(TestSingletonPerThreadClass(self.THREAD_NAME_2))
                TestSingletonPerThreadClass.clear()
            except Exception as e:
                err.put(str(e))

        output = Queue()
        # Getting the initial instances in the first run
        self._setup_mutithread_and_execute(func1=self._get_test_class_instance,
                                           args1=(output, self.errors, self.THREAD_NAME_1),
                                           func2=get_and_clear_test_class_instance,
                                           args2=(output, self.errors))

        self.assertEqual(2, output.qsize())

        t1_obj, t2_obj = self._parse_output_and_return_thread_objects(output)
        self.assertNotEqual(t1_obj.uuid, t2_obj.uuid)

        output = Queue()    # Re-initialize the queue
        # Running the same again to verify that clear() only removes class object for the thread where it's called
        self._setup_mutithread_and_execute(func1=self._get_test_class_instance,
                                           args1=(output, self.errors, self.THREAD_NAME_1),
                                           func2=get_and_clear_test_class_instance,
                                           args2=(output, self.errors))

        self.assertEqual(2, output.qsize())

        new_t1_obj, new_t2_obj = self._parse_output_and_return_thread_objects(output)

        self.assertNotEqual(new_t1_obj.uuid, new_t2_obj.uuid)
        self.assertEqual(t1_obj.uuid, new_t1_obj.uuid, "Clear was not called for thread-1, the objects should be same")
        self.assertNotEqual(t2_obj.uuid, new_t2_obj.uuid, "Clear was called for thread-2, the objects should not be same")

    def test_it_should_return_existing_instance_for_new_thread_with_same_name(self):

        output = Queue()
        self._setup_mutithread_and_execute(func1=self._get_test_class_instance,
                                           args1=(output, self.errors, self.THREAD_NAME_1),
                                           func2=self._get_test_class_instance,
                                           args2=(output, self.errors, self.THREAD_NAME_2))

        t1_obj, t2_obj = self._parse_output_and_return_thread_objects(output)

        output = Queue()
        # The 2nd call is to get new objects with the same thread name to verify if the objects are same
        self._setup_mutithread_and_execute(func1=self._get_test_class_instance,
                                           args1=(output, self.errors, self.THREAD_NAME_1),
                                           func2=self._get_test_class_instance,
                                           args2=(output, self.errors, self.THREAD_NAME_2))

        new_t1_obj, new_t2_obj = self._parse_output_and_return_thread_objects(output)

        self.assertEqual(t1_obj.name, new_t1_obj.name)
        self.assertEqual(t1_obj.uuid, new_t1_obj.uuid)
        self.assertEqual(t2_obj.name, new_t2_obj.name)
        self.assertEqual(t2_obj.uuid, new_t2_obj.uuid)
