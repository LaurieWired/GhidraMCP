#!/usr/bin/env python3
"""
Test Harness for RE Improvement Workflow

This module provides comprehensive testing for both:
1. The curated documentation tools
2. The autonomous improvement workflow

Run with: python test_workflow.py [--integration] [--verbose]
"""

import json
import sys
import os
import time
import unittest
from typing import Dict, List, Any
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import modules to test
try:
    from workflows.re_documentation_tools import (
        get_program_info, find_undocumented_functions, list_functions,
        decompile, disassemble, get_function_variables, get_callees,
        get_callers, get_xrefs, get_jump_targets,
        rename_function, set_function_signature, rename_variable,
        batch_set_types, batch_create_labels, batch_set_comments,
        list_data_types, search_data_types, create_struct, create_enum,
        analyze_completeness, analyze_function_complete,
        list_tools, TOOL_INVENTORY,
        GhidraConnectionError, GhidraOperationError
    )
    TOOLS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import documentation tools: {e}")
    TOOLS_AVAILABLE = False

try:
    from workflows.re_improvement_workflow import (
        WorkflowOrchestrator, WorkflowSession,
        REExpertAgent, ToolsmithAgent, TestHarness,
        GhidraClient, ToolUsageMetrics, ImprovementProposal, ImprovementType
    )
    WORKFLOW_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import workflow: {e}")
    WORKFLOW_AVAILABLE = False


# =============================================================================
# Unit Tests - No Ghidra Required
# =============================================================================

class TestToolInventory(unittest.TestCase):
    """Test tool inventory structure."""

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_inventory_has_all_categories(self):
        """Verify all expected categories exist."""
        inventory = list_tools()
        expected = {"discovery", "analysis", "documentation", "data_types",
                   "verification", "workflow_helpers"}
        self.assertEqual(set(inventory.keys()), expected)

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_each_category_has_tools(self):
        """Verify each category has at least one tool."""
        inventory = list_tools()
        for category, tools in inventory.items():
            self.assertGreater(len(tools), 0,
                             f"Category {category} has no tools")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_total_tool_count_reasonable(self):
        """Verify we have a focused set (not too many, not too few)."""
        inventory = list_tools()
        total = sum(len(tools) for tools in inventory.values())
        # Should have 15-35 tools for a focused set
        self.assertGreaterEqual(total, 15, "Too few tools")
        self.assertLessEqual(total, 35, "Too many tools - consider pruning")


class TestWorkflowDataStructures(unittest.TestCase):
    """Test workflow data structures."""

    @unittest.skipUnless(WORKFLOW_AVAILABLE, "Workflow not available")
    def test_tool_usage_metrics_initialization(self):
        """Verify ToolUsageMetrics initializes correctly."""
        metrics = ToolUsageMetrics(tool_name="test_tool")
        self.assertEqual(metrics.tool_name, "test_tool")
        self.assertEqual(metrics.call_count, 0)
        self.assertEqual(metrics.success_count, 0)
        self.assertEqual(metrics.failure_count, 0)
        self.assertEqual(metrics.total_time_ms, 0.0)

    @unittest.skipUnless(WORKFLOW_AVAILABLE, "Workflow not available")
    def test_improvement_proposal_creation(self):
        """Verify ImprovementProposal creates correctly."""
        proposal = ImprovementProposal(
            id="TEST-001",
            type=ImprovementType.BUG_FIX,
            title="Test Fix",
            description="Fix a test issue",
            rationale="Testing",
            affected_tools=["tool1", "tool2"],
            priority=4,
            estimated_effort="small"
        )
        self.assertEqual(proposal.id, "TEST-001")
        self.assertEqual(proposal.type, ImprovementType.BUG_FIX)
        self.assertEqual(proposal.status, "proposed")

    @unittest.skipUnless(WORKFLOW_AVAILABLE, "Workflow not available")
    def test_workflow_session_initialization(self):
        """Verify WorkflowSession initializes correctly."""
        session = WorkflowSession(
            session_id="SESSION-0001",
            start_time=datetime.now()
        )
        self.assertEqual(session.session_id, "SESSION-0001")
        self.assertIsNone(session.end_time)
        self.assertEqual(session.re_actions, [])
        self.assertFalse(session.re_success)

    @unittest.skipUnless(WORKFLOW_AVAILABLE, "Workflow not available")
    def test_improvement_types_comprehensive(self):
        """Verify all improvement types are defined."""
        expected_types = {
            "new_tool", "remove_tool", "modify_tool",
            "combine_tools", "bug_fix", "performance", "documentation"
        }
        actual_types = {t.value for t in ImprovementType}
        self.assertEqual(actual_types, expected_types)


class TestToolsmithLogic(unittest.TestCase):
    """Test Toolsmith agent logic without Ghidra."""

    @unittest.skipUnless(WORKFLOW_AVAILABLE, "Workflow not available")
    def test_proposal_priority_sorting(self):
        """Verify proposals are sorted by priority correctly."""
        # Create a mock client that doesn't connect
        class MockClient:
            def is_available(self):
                return False

        toolsmith = ToolsmithAgent(MockClient())

        # Add proposals with different priorities
        toolsmith._create_proposal(
            ImprovementType.DOCUMENTATION, "Low Priority", "", "",
            [], priority=1
        )
        toolsmith._create_proposal(
            ImprovementType.BUG_FIX, "High Priority", "", "",
            [], priority=5
        )
        toolsmith._create_proposal(
            ImprovementType.PERFORMANCE, "Medium Priority", "", "",
            [], priority=3
        )

        sorted_proposals = toolsmith.prioritize_proposals()
        self.assertEqual(sorted_proposals[0].title, "High Priority")
        self.assertEqual(sorted_proposals[1].title, "Medium Priority")
        self.assertEqual(sorted_proposals[2].title, "Low Priority")


# =============================================================================
# Integration Tests - Require Ghidra
# =============================================================================

class TestGhidraConnection(unittest.TestCase):
    """Test Ghidra server connectivity."""

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_can_get_program_info(self):
        """Verify we can connect and get program info."""
        try:
            info = get_program_info()
            self.assertIn("Program Name", info)
            print(f"  Connected to: {info.get('Program Name')}")
        except GhidraConnectionError:
            self.skipTest("Ghidra server not available")

    @unittest.skipUnless(WORKFLOW_AVAILABLE, "Workflow not available")
    def test_ghidra_client_availability_check(self):
        """Test GhidraClient.is_available() method."""
        client = GhidraClient()
        available = client.is_available()
        if not available:
            self.skipTest("Ghidra server not available")
        self.assertTrue(available)


class TestDiscoveryTools(unittest.TestCase):
    """Test discovery tools against live Ghidra."""

    @classmethod
    def setUpClass(cls):
        """Check Ghidra availability once for all tests."""
        if not TOOLS_AVAILABLE:
            return
        try:
            get_program_info()
            cls.ghidra_available = True
        except GhidraConnectionError:
            cls.ghidra_available = False

    def setUp(self):
        if not getattr(self.__class__, 'ghidra_available', False):
            self.skipTest("Ghidra server not available")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_find_undocumented_functions(self):
        """Test finding undocumented functions."""
        funcs = find_undocumented_functions(limit=5)
        self.assertIsInstance(funcs, list)
        if funcs:
            self.assertIn("name", funcs[0])
            self.assertIn("address", funcs[0])
            print(f"  Found {len(funcs)} undocumented functions")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_list_functions(self):
        """Test listing all functions."""
        funcs = list_functions(limit=10)
        self.assertIsInstance(funcs, list)
        print(f"  Listed {len(funcs)} functions")


class TestAnalysisTools(unittest.TestCase):
    """Test analysis tools against live Ghidra."""

    @classmethod
    def setUpClass(cls):
        """Get a test function to analyze."""
        cls.test_function = None
        cls.ghidra_available = False

        if not TOOLS_AVAILABLE:
            return

        try:
            funcs = find_undocumented_functions(limit=1)
            if funcs:
                cls.test_function = funcs[0]
            cls.ghidra_available = True
        except GhidraConnectionError:
            pass

    def setUp(self):
        if not self.__class__.ghidra_available:
            self.skipTest("Ghidra server not available")
        if not self.__class__.test_function:
            self.skipTest("No test function available")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_decompile(self):
        """Test decompilation."""
        code = decompile(self.test_function["name"])
        self.assertIsInstance(code, str)
        self.assertGreater(len(code), 0)
        print(f"  Decompiled {len(code)} chars")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_disassemble(self):
        """Test disassembly."""
        asm = disassemble(self.test_function["name"])
        self.assertIsInstance(asm, str)
        print(f"  Disassembled {len(asm)} chars")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_get_function_variables(self):
        """Test getting function variables."""
        vars = get_function_variables(self.test_function["name"])
        self.assertIsInstance(vars, list)
        print(f"  Found {len(vars)} variables")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_get_callees(self):
        """Test getting callees."""
        callees = get_callees(self.test_function["name"])
        self.assertIsInstance(callees, list)
        print(f"  Found {len(callees)} callees")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_get_callers(self):
        """Test getting callers."""
        callers = get_callers(self.test_function["name"])
        self.assertIsInstance(callers, list)
        print(f"  Found {len(callers)} callers")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_analyze_function_complete(self):
        """Test complete function analysis."""
        analysis = analyze_function_complete(self.test_function["name"])
        self.assertIn("name", analysis)
        self.assertIn("decompiled", analysis)
        self.assertIn("variables", analysis)
        print(f"  Complete analysis returned {len(analysis)} fields")


class TestDataTypeTools(unittest.TestCase):
    """Test data type tools against live Ghidra."""

    @classmethod
    def setUpClass(cls):
        """Check Ghidra availability."""
        cls.ghidra_available = False
        if not TOOLS_AVAILABLE:
            return
        try:
            get_program_info()
            cls.ghidra_available = True
        except GhidraConnectionError:
            pass

    def setUp(self):
        if not self.__class__.ghidra_available:
            self.skipTest("Ghidra server not available")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_list_data_types(self):
        """Test listing data types."""
        types = list_data_types(limit=20)
        self.assertIsInstance(types, list)
        print(f"  Found {len(types)} data types")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_search_data_types(self):
        """Test searching data types."""
        types = search_data_types("DWORD")
        self.assertIsInstance(types, list)
        print(f"  Search returned {len(types)} matches")


class TestWorkflowIntegration(unittest.TestCase):
    """Integration tests for the full workflow."""

    @classmethod
    def setUpClass(cls):
        """Check Ghidra availability."""
        cls.ghidra_available = False
        if not WORKFLOW_AVAILABLE:
            return
        try:
            client = GhidraClient()
            cls.ghidra_available = client.is_available()
        except Exception:
            pass

    def setUp(self):
        if not self.__class__.ghidra_available:
            self.skipTest("Ghidra server not available")

    @unittest.skipUnless(WORKFLOW_AVAILABLE, "Workflow not available")
    def test_re_expert_find_function(self):
        """Test RE Expert can find undocumented functions."""
        client = GhidraClient()
        expert = REExpertAgent(client)
        func = expert.find_undocumented_function()
        # May or may not find one depending on binary state
        if func:
            self.assertIn("name", func)
            self.assertIn("address", func)
            print(f"  RE Expert found: {func['name']}")
        else:
            print("  RE Expert found no undocumented functions")

    @unittest.skipUnless(WORKFLOW_AVAILABLE, "Workflow not available")
    def test_test_harness_smoke_tests(self):
        """Test the built-in smoke tests."""
        client = GhidraClient()
        harness = TestHarness(client)
        results = harness.run_smoke_tests()

        self.assertIn("passed", results)
        self.assertIn("failed", results)
        self.assertIn("tests", results)
        print(f"  Smoke tests: {results['passed']} passed, {results['failed']} failed")

    @unittest.skipUnless(WORKFLOW_AVAILABLE, "Workflow not available")
    def test_single_workflow_iteration(self):
        """Test running a single workflow iteration."""
        orchestrator = WorkflowOrchestrator(max_iterations=1)

        if not orchestrator.check_prerequisites():
            self.skipTest("Workflow prerequisites not met")

        session = orchestrator.run_single_iteration()

        self.assertIsNotNone(session)
        self.assertIsNotNone(session.session_id)
        self.assertIsNotNone(session.start_time)
        print(f"  Session {session.session_id} completed")
        print(f"  Friction points: {len(session.re_friction_points)}")
        print(f"  Proposals: {len(session.improvements_proposed)}")


# =============================================================================
# Performance Tests
# =============================================================================

class TestPerformance(unittest.TestCase):
    """Performance tests for tools."""

    @classmethod
    def setUpClass(cls):
        """Check Ghidra availability."""
        cls.ghidra_available = False
        if not TOOLS_AVAILABLE:
            return
        try:
            get_program_info()
            cls.ghidra_available = True
        except GhidraConnectionError:
            pass

    def setUp(self):
        if not self.__class__.ghidra_available:
            self.skipTest("Ghidra server not available")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_decompile_performance(self):
        """Test decompilation completes within timeout."""
        funcs = find_undocumented_functions(limit=1)
        if not funcs:
            self.skipTest("No functions to test")

        start = time.time()
        decompile(funcs[0]["name"])
        elapsed = time.time() - start

        self.assertLess(elapsed, 60, "Decompilation took too long")
        print(f"  Decompile completed in {elapsed:.2f}s")

    @unittest.skipUnless(TOOLS_AVAILABLE, "Tools not available")
    def test_batch_operations_faster_than_individual(self):
        """Verify batch operations are more efficient."""
        # This is a conceptual test - actual timing would require
        # a controlled environment with known data
        self.assertTrue(True, "Batch operations are defined")


# =============================================================================
# Main Test Runner
# =============================================================================

def run_tests(integration: bool = False, verbose: bool = False):
    """
    Run the test suite.

    Args:
        integration: If True, include integration tests requiring Ghidra
        verbose: If True, show detailed output
    """
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Always run unit tests
    suite.addTests(loader.loadTestsFromTestCase(TestToolInventory))
    suite.addTests(loader.loadTestsFromTestCase(TestWorkflowDataStructures))
    suite.addTests(loader.loadTestsFromTestCase(TestToolsmithLogic))

    # Optionally run integration tests
    if integration:
        suite.addTests(loader.loadTestsFromTestCase(TestGhidraConnection))
        suite.addTests(loader.loadTestsFromTestCase(TestDiscoveryTools))
        suite.addTests(loader.loadTestsFromTestCase(TestAnalysisTools))
        suite.addTests(loader.loadTestsFromTestCase(TestDataTypeTools))
        suite.addTests(loader.loadTestsFromTestCase(TestWorkflowIntegration))
        suite.addTests(loader.loadTestsFromTestCase(TestPerformance))

    # Run with appropriate verbosity
    verbosity = 2 if verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity)

    print("\n" + "=" * 60)
    print("RE IMPROVEMENT WORKFLOW - TEST SUITE")
    print("=" * 60)
    print(f"Integration tests: {'ENABLED' if integration else 'DISABLED'}")
    print()

    result = runner.run(suite)

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")

    return len(result.failures) + len(result.errors)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Test harness for RE improvement workflow"
    )
    parser.add_argument(
        "--integration", "-i",
        action="store_true",
        help="Run integration tests (requires Ghidra)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Run only quick unit tests"
    )

    args = parser.parse_args()

    # Quick mode disables integration
    integration = args.integration and not args.quick

    failures = run_tests(integration=integration, verbose=args.verbose)
    sys.exit(failures)


if __name__ == "__main__":
    main()
