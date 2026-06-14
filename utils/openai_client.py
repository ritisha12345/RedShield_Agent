"""Shared OpenAI client helper for RedShield agents."""

from __future__ import annotations

import os
from typing import Any

from utils.retry import retry_call


def call_openai_json(
    *,
    system_prompt: str,
    user_prompt: str,
    env_model_name: str,
    default_model: str,
    temperature: float,
    max_tokens: int,
    client: Any | None = None,
    model: str | None = None,
    empty_response_message: str = "OpenAI returned an empty response.",
) -> str:
    """Call OpenAI chat completions and return JSON response text."""

    selected_model = select_model(
        explicit_model=model,
        env_model_name=env_model_name,
        default_model=default_model,
    )
    openai_client = client or build_openai_client()

    def operation() -> str:
        response = openai_client.chat.completions.create(
            model=selected_model,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        content = response.choices[0].message.content
        if not content:
            raise ValueError(empty_response_message)
        return content

    return retry_call(operation)


def select_model(
    *,
    explicit_model: str | None,
    env_model_name: str,
    default_model: str,
) -> str:
    """Select a model from explicit override, environment, or default."""

    if explicit_model:
        return explicit_model
    env_model = os.getenv(env_model_name)
    if env_model:
        return env_model
    return default_model


def build_openai_client() -> Any:
    """Create an OpenAI client lazily so imports stay testable."""

    _load_dotenv_if_available()

    try:
        from openai import OpenAI
    except ModuleNotFoundError as error:
        raise RuntimeError(
            "The openai package is required for RedShield OpenAI calls. "
            "Install project dependencies with `pip install -r requirements.txt`."
        ) from error

    try:
        return OpenAI()
    except Exception as error:
        raise RuntimeError(
            "Failed to initialize the OpenAI client. Check OPENAI_API_KEY."
        ) from error


def _load_dotenv_if_available() -> None:
    """Load local environment variables if python-dotenv is installed."""

    try:
        from dotenv import load_dotenv
    except ModuleNotFoundError:
        return

    load_dotenv()
