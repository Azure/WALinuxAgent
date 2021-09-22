import os

from dcr.scenario_utils.test_orchestrator import TestObj, TestOrchestrator
from ext_seq import ExtensionSequencingTestClass
from ext_seq_tests import add_extensions_with_dependency_template, remove_dependent_extension_template, \
    remove_all_dependencies_template, add_more_dependencies_template, single_dependencies_template, \
    delete_extensions_template


def main():
    ext_seq = ExtensionSequencingTestClass()

    tests = [
        TestObj("Add Extensions with dependencies", lambda: ext_seq.run(add_extensions_with_dependency_template())),
        TestObj("Remove dependent extension", lambda: ext_seq.run(remove_dependent_extension_template())),
        TestObj("Remove all dependencies", lambda: ext_seq.run(remove_all_dependencies_template())),
        TestObj("Add more dependencies", lambda: ext_seq.run(add_more_dependencies_template())),
        TestObj("single dependencies", lambda: ext_seq.run(single_dependencies_template())),
        TestObj("Delete extensions", lambda: ext_seq.run(delete_extensions_template()))
    ]

    test_orchestrator = TestOrchestrator("ExtSeqDependency-Host", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report(
        os.path.join(os.environ['BUILD_ARTIFACTSTAGINGDIRECTORY'], "test-results-ext-seq-host.xml"))
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"


if __name__ == '__main__':
    main()
