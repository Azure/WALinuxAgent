class ThreadHandlerInterface(object):
    """
    Interface for all thread handlers created and maintained by the GuestAgent.
    """

    @staticmethod
    def get_thread_name():
        raise NotImplementedError("get_thread_name() not implemented")

    def run(self):
        raise NotImplementedError("run() not implemented")

    def is_alive(self):
        raise NotImplementedError("is_alive() not implemented")

    def start(self):
        raise NotImplementedError("start() not implemented")

    def stop(self):
        raise NotImplementedError("stop() not implemented")