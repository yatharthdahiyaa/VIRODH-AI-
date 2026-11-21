"""Benign pass-through 'attack': sends the behavior's prompt and image unchanged (for benign / FPR runs)."""
from __future__ import annotations

from core.base_classes import BaseAttack
from core.data_formats import TestCase


class PassthroughAttack(BaseAttack):
    def generate_test_case(self, original_prompt: str, image_path: str, case_id: str, **kwargs) -> TestCase:
        return self.create_test_case(
            case_id=case_id,
            jailbreak_prompt=original_prompt,
            jailbreak_image_path=str(image_path),
            original_prompt=original_prompt,
            original_image_path=str(image_path),
            metadata={"payload_kind": "benign"},
        )
