"""
LangGraph Multi-Agent Workflow.
Pipeline: security_scanner -> test_generator -> patch_creator -> judge -> (retry or END).
"""

from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph

from src.agents.judge import judge_node
from src.agents.patch_creator import patch_creator_node
from src.agents.security_scanner import security_scanner_node
from src.agents.state import AgentState
from src.agents.test_generator import test_generator_node

logger = logging.getLogger("codesentinel.agents.graph")


def should_continue_review(state: AgentState) -> str:
    """Route back to patch_creator if Judge rejected the patch and iterations < 3."""
    approval = state.get("judge_approval", False)
    iterations = state.get("iteration_count", 0)

    if not approval and iterations < 3:
        logger.info(
            "[graph] judge rejected patch; cycling back to patch_creator (iteration %d/3)",
            iterations,
        )
        return "patch_creator"

    return END


def build_code_sentinel_graph():
    """Construct and compile the cyclical LangGraph workflow."""
    workflow = StateGraph(AgentState)

    workflow.add_node("security_scanner", security_scanner_node)
    workflow.add_node("test_generator", test_generator_node)
    workflow.add_node("patch_creator", patch_creator_node)
    workflow.add_node("judge", judge_node)

    workflow.add_edge(START, "security_scanner")
    workflow.add_edge("security_scanner", "test_generator")
    workflow.add_edge("test_generator", "patch_creator")
    workflow.add_edge("patch_creator", "judge")

    workflow.add_conditional_edges(
        "judge",
        should_continue_review,
        {
            "patch_creator": "patch_creator",
            END: END,
        },
    )

    return workflow.compile()


sentinel_graph = build_code_sentinel_graph()


async def run_code_sentinel_workflow(state: AgentState) -> AgentState:
    """Execute the compiled multi-agent graph on an initial PR state."""
    pr_num = state.get("pr_number", 0)
    logger.info("[graph] starting audit workflow for PR #%d", pr_num)
    final_state: AgentState = await sentinel_graph.ainvoke(state)
    logger.info("[graph] finished audit workflow for PR #%d", pr_num)
    return final_state
