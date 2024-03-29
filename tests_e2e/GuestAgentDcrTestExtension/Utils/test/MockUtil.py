#!/usr/bin/env python
#
# Sample Extension
#
# Copyright 2014 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# pylint: disable=all

# TODO: These tests were copied as reference - they are not currently running

class MockUtil():
    def __init__(self, test):
        self.test = test

    def get_log_dir(self):
        return "/tmp"

    def log(self, msg):
        print(msg)

    def error(self, msg):
        print(msg)

    def get_seq_no(self):
        return "0"

    def do_status_report(self, operation, status, status_code, message):
        self.test.assertNotEqual(None, message)
        self.last = "do_status_report"

    def do_exit(self,exit_code,operation,status,code,message):
        self.test.assertNotEqual(None, message)
        self.last = "do_exit"
