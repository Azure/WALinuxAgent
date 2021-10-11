from dcr.scenario_utils.test_orchestrator import TestFuncObj, TestOrchestrator
from ext_seq import ExtensionSequencingTestClass
from ext_seq_tests import add_extensions_with_dependency_template, remove_dependent_extension_template, \
    remove_all_dependencies_template, add_more_dependencies_template, single_dependencies_template, \
    delete_extensions_template


def main():
    ext_seq = ExtensionSequencingTestClass()

    tests = [
        TestFuncObj("Add Extensions with dependencies", lambda: ext_seq.run(add_extensions_with_dependency_template()), raise_on_error=True),
        TestFuncObj("Remove dependent extension", lambda: ext_seq.run(remove_dependent_extension_template())),
        TestFuncObj("Remove all dependencies", lambda: ext_seq.run(remove_all_dependencies_template())),
        TestFuncObj("Add more dependencies", lambda: ext_seq.run(add_more_dependencies_template())),
        TestFuncObj("single dependencies", lambda: ext_seq.run(single_dependencies_template())),
        TestFuncObj("Delete extensions", lambda: ext_seq.run(delete_extensions_template()))
    ]

    test_orchestrator = TestOrchestrator("ExtSeqDependency-Host", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report_on_orchestrator("test-results-ext-seq-host.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"


if __name__ == '__main__':
    main()
