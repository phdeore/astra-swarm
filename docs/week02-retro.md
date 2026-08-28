# Astra-Swarm - Milestone 2 Retrospective

Attempted prompt caching per the sprint plan. Verified the caching path works with a >4,096-token block (Haiku 4.5's minimum). Astra-Swarm's current cacheable prefix (~1,000 tokens) is below threshold, so caching provides no benefit at Week 2's context size. Re-evaluate in Week 3 once LangGraph state grows the context.