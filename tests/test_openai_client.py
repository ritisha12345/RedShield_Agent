"""Tests for the shared OpenAI client helper."""

import unittest
from unittest.mock import patch

from utils.openai_client import call_openai_json, select_model


class _Message:
    def __init__(self, content: str | None) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str | None) -> None:
        self.message = _Message(content)


class _Response:
    def __init__(self, content: str | None) -> None:
        self.choices = [_Choice(content)]


class _Completions:
    def __init__(self, content: str | None) -> None:
        self.content = content
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _Response(self.content)


class _Chat:
    def __init__(self, completions: _Completions) -> None:
        self.completions = completions


class _FakeClient:
    def __init__(self, content: str | None) -> None:
        self.completions = _Completions(content)
        self.chat = _Chat(self.completions)


class OpenAIClientTests(unittest.TestCase):
    def test_select_model_prefers_explicit_model(self) -> None:
        with patch.dict("os.environ", {"TEST_MODEL": "env-model"}):
            self.assertEqual(
                select_model(
                    explicit_model="explicit-model",
                    env_model_name="TEST_MODEL",
                    default_model="default-model",
                ),
                "explicit-model",
            )

    def test_select_model_uses_environment_before_default(self) -> None:
        with patch.dict("os.environ", {"TEST_MODEL": "env-model"}):
            self.assertEqual(
                select_model(
                    explicit_model=None,
                    env_model_name="TEST_MODEL",
                    default_model="default-model",
                ),
                "env-model",
            )

    def test_call_openai_json_uses_json_response_format(self) -> None:
        client = _FakeClient('{"ok": true}')

        content = call_openai_json(
            system_prompt="system",
            user_prompt="user",
            env_model_name="TEST_MODEL",
            default_model="default-model",
            temperature=0.1,
            max_tokens=123,
            client=client,
            model="explicit-model",
            empty_response_message="empty",
        )

        self.assertEqual(content, '{"ok": true}')
        call = client.completions.calls[0]
        self.assertEqual(call["model"], "explicit-model")
        self.assertEqual(call["temperature"], 0.1)
        self.assertEqual(call["max_tokens"], 123)
        self.assertEqual(call["response_format"], {"type": "json_object"})
        self.assertEqual(call["messages"][0]["content"], "system")
        self.assertEqual(call["messages"][1]["content"], "user")

    def test_call_openai_json_rejects_empty_response(self) -> None:
        client = _FakeClient(None)

        with self.assertRaises(ValueError):
            call_openai_json(
                system_prompt="system",
                user_prompt="user",
                env_model_name="TEST_MODEL",
                default_model="default-model",
                temperature=0.1,
                max_tokens=123,
                client=client,
                empty_response_message="empty",
            )


if __name__ == "__main__":
    unittest.main()
