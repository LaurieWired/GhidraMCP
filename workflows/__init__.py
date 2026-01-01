"""
RE Improvement Workflow Package

This package provides an autonomous workflow for continuously improving
the Ghidra MCP tooling based on actual reverse engineering usage patterns.

Modules:
    re_documentation_tools: Curated minimal tool set for binary documentation
    re_improvement_workflow: Autonomous improvement loop with RE Expert and Toolsmith agents
    continuous_improvement: Main orchestrator for autonomous documentation
    ghidra_manager: Ghidra process lifecycle management
    claude_analyzer: Claude API integration for automated analysis
    session_reporter: Session statistics and reporting
    quality_tracker: Documentation completeness tracking
    dashboard: CLI progress dashboard
    test_workflow: Test harness for validating the workflow

Usage:
    # Run the autonomous improvement workflow
    python -m workflows.re_improvement_workflow --iterations 5

    # Run the dashboard
    python -m workflows.dashboard

    # Run tests
    python -m workflows.test_workflow --integration

    # Use the curated tools directly
    from workflows.re_documentation_tools import (
        decompile, analyze_function_complete, document_function_batch
    )

    # Use the autonomous workflow
    from workflows.continuous_improvement import (
        ContinuousImprovementLoop, ensure_ghidra, check_ghidra_status
    )

    # Use Claude for analysis
    from workflows.claude_analyzer import (
        ClaudeAnalyzer, AutoDocumenter, analyze_single_function
    )
"""

from .re_documentation_tools import (
    # Discovery
    get_program_info,
    find_undocumented_functions,
    list_functions,

    # Analysis
    decompile,
    disassemble,
    get_function_variables,
    get_callees,
    get_callers,
    get_xrefs,
    get_jump_targets,

    # Documentation
    rename_function,
    set_function_signature,
    rename_variable,
    set_variable_type,
    batch_set_types,
    create_label,
    batch_create_labels,
    set_plate_comment,
    batch_set_comments,

    # Data Types
    list_data_types,
    search_data_types,
    create_struct,
    create_enum,
    apply_data_type,

    # Verification
    analyze_completeness,
    get_function_info,

    # Workflow Helpers
    analyze_function_complete,
    document_function_batch,

    # Inventory
    list_tools,
    TOOL_INVENTORY,

    # Exceptions
    GhidraConnectionError,
    GhidraOperationError,
)

from .re_improvement_workflow import (
    WorkflowOrchestrator,
    WorkflowSession,
    REExpertAgent,
    ToolsmithAgent,
    TestHarness,
    GhidraClient,
    ToolUsageMetrics,
    ImprovementProposal,
    ImprovementType,
)

from .continuous_improvement import (
    ContinuousImprovementLoop,
    ImprovementState,
    ensure_ghidra,
    restart_ghidra,
    check_ghidra_status,
    configure_ghidra_defaults,
    get_loop_instance,
)

from .ghidra_manager import (
    GhidraManager,
    GhidraConfig,
    GhidraState,
)

from .claude_analyzer import (
    ClaudeAnalyzer,
    AutoDocumenter,
    AnalysisResult,
    create_analyzer,
    analyze_single_function,
    run_auto_documentation_session,
)

from .session_reporter import (
    SessionReporter,
    SessionHistory,
    generate_report,
    get_history_summary,
)

from .quality_tracker import (
    QualityTracker,
    QualityHistory,
    check_quality,
    get_priority_functions,
)

__version__ = "1.1.0"
__all__ = [
    # Documentation Tools
    "get_program_info",
    "find_undocumented_functions",
    "list_functions",
    "decompile",
    "disassemble",
    "get_function_variables",
    "get_callees",
    "get_callers",
    "get_xrefs",
    "get_jump_targets",
    "rename_function",
    "set_function_signature",
    "rename_variable",
    "set_variable_type",
    "batch_set_types",
    "create_label",
    "batch_create_labels",
    "set_plate_comment",
    "batch_set_comments",
    "list_data_types",
    "search_data_types",
    "create_struct",
    "create_enum",
    "apply_data_type",
    "analyze_completeness",
    "get_function_info",
    "analyze_function_complete",
    "document_function_batch",
    "list_tools",
    "TOOL_INVENTORY",
    "GhidraConnectionError",
    "GhidraOperationError",

    # Workflow Components
    "WorkflowOrchestrator",
    "WorkflowSession",
    "REExpertAgent",
    "ToolsmithAgent",
    "TestHarness",
    "GhidraClient",
    "ToolUsageMetrics",
    "ImprovementProposal",
    "ImprovementType",

    # Continuous Improvement
    "ContinuousImprovementLoop",
    "ImprovementState",
    "ensure_ghidra",
    "restart_ghidra",
    "check_ghidra_status",
    "configure_ghidra_defaults",
    "get_loop_instance",

    # Ghidra Manager
    "GhidraManager",
    "GhidraConfig",
    "GhidraState",

    # Claude Analyzer
    "ClaudeAnalyzer",
    "AutoDocumenter",
    "AnalysisResult",
    "create_analyzer",
    "analyze_single_function",
    "run_auto_documentation_session",

    # Session Reporting
    "SessionReporter",
    "SessionHistory",
    "generate_report",
    "get_history_summary",

    # Quality Tracking
    "QualityTracker",
    "QualityHistory",
    "check_quality",
    "get_priority_functions",
]
