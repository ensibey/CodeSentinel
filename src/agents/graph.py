"""
LangGraph Multi-Agent Cyclical Workflow.
Orchestrates the collaborative audit pipeline:
Security Scanner -> Test Generator -> Patch Creator -> Judge -> (Cyclic Self-Correction or END)
"""

from __future__ import annotations
import logging
from typing import Any, Dict

from langgraph.graph import END, START, StateGraph

from src.agents.judge import judge_node
from src.agents.patch_creator import patch_creator_node
from src.agents.security_scanner import security_scanner_node
from src.agents.state import AgentState
from src.agents.test_generator import test_generator_node

logger = logging.getLogger("codesentinel.agents.graph")


def should_continue_review(state: AgentState) -> str:
    """
    Conditional Edge Decision Function.
    Determines whether the multi-agent graph should cycle back for refinement
    or conclude review delivery.
    """
    approval = state.get("judge_approval", False)
    iterations = state.get("iteration_count", 0)

    # If Judge rejected the patch and we have not exceeded the 3-cycle limit
    if not approval and iterations < 3:
        logger.info(
            "🔁 Self-Correction Triggered: Judge rejected patch. Cycling back to patch_creator (Iteration: %d/3).",
            iterations,
        )
        return "patch_creator"

    logger.info("🏁 Audit Completed: Judge approved or iteration threshold reached.")
    return END


def build_code_sentinel_graph():
    """
    Constructs and compiles the Cyclical LangGraph StateGraph.
    """
    logger.info("Constructing CodeSentinel Multi-Agent StateGraph...")
    workflow = StateGraph(AgentState)

    # 1. Add Agent Nodes
    workflow.add_node("security_scanner", security_scanner_node)
    workflow.add_node("test_generator", test_generator_node)
    workflow.add_node("patch_creator", patch_creator_node)
    workflow.add_node("judge", judge_node)

    # 2. Add Linear Flow Edges
    workflow.add_edge(START, "security_scanner")
    workflow.add_edge("security_scanner", "test_generator")
    workflow.add_edge("test_generator", "patch_creator")
    workflow.add_edge("patch_creator", "judge")

    # 3. Add Conditional Self-Correction Edge
    workflow.add_conditional_edges(
        "judge",
        should_continue_review,
        {
            "patch_creator": "patch_creator",
            END: END,
        },
    )

    app = workflow.compile()
    logger.info("✅ CodeSentinel Multi-Agent StateGraph compiled successfully.")
    return app


# Singleton compiled graph instance
sentinel_graph = build_code_sentinel_graph()


async def run_code_sentinel_workflow(state: AgentState) -> AgentState:
    """
    Asynchronous runner invoking the multi-agent graph with the initial state.
    """
    logger.info("🚀 Launching CodeSentinel Multi-Agent review for PR #%d...", state.get("pr_number", 0))
    final_state: AgentState = await sentinel_graph.ainvoke(state)
    logger.info("✨ CodeSentinel workflow completed for PR #%d.", state.get("pr_number", 0))
    return final_state
