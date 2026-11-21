"""Adversarial image security engine — independent of the multimodal jailbreak engine.

Detects *suspicious image characteristics* and *prediction instability* on a local classifier.
It does not identify the attack family of an unknown image, and results on the local
classifier are not evidence of a successful attack on a hosted VLM.
"""
