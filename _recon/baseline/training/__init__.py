"""NivXRay LLM training pipeline — process-tree schema, seed archetypes, predictor.

Modules:
    schema         · canonical Pydantic models (ProcessNode / ProcessTree / SocRationale / TrainingRecord)
    system_prompt  · strict anti-hallucination system prompt for the NivXRay Parser
    tree_formats   · nested-JSON ↔ flat edge-list ↔ ASCII tree converters
    validator      · post-generation citation & IOC validation / pruning
    predictor      · Emergent-LLM-key backed tree prediction
    seed_dataset   · 100+ archetypes (Windows + Linux + macOS + container)
    exporter       · JSONL / OpenAI-chat / Anthropic-turn / CSV emitters
"""
