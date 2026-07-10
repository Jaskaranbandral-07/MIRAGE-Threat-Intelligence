"""
MIRAGE Analytics Engine
=======================
Statistical analysis pipeline for honeypot session data.
All classification is rule-based or statistical — zero LLM/generative-AI calls.

Modules:
    feature_extractor : Per-session feature vector extraction
    clustering        : DBSCAN-based campaign clustering
    attack_tagger     : Rule-based MITRE ATT&CK technique tagging
    bot_detector      : Statistical bot-vs-human classification
    run_analytics     : Full pipeline orchestration
"""
