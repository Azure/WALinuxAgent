#!/bin/bash

for i in {1..10000}
do
    echo $i
    nosetests tests/utils/test_extension_process_util.py:TestProcessUtils.test_handle_process_completion_should_raise_on_timeout || \
    exit
done
