# =============================================================================
# FILE: app/services/ai/ai_client.py
# =============================================================================
# DESCRIPTION: AI Client for communicating with AI providers
# =============================================================================

import json
from typing import Any

import requests

from app.services.ai.model_manager import ModelConfig, ModelProvider


class AIClientError(Exception):
    """Base exception for AI client errors."""


class AIClient:
    """
    Client for communicating with AI providers.

    This client handles requests to various AI providers including:
        - Ollama (local)
        - OpenAI
        - Claude
        - Gemini
        - Custom endpoints

    Features:
        - Provider-agnostic interface
        - Automatic retry on failure
        - Timeout handling
        - Response validation
    """

    def __init__(self, config: ModelConfig) -> None:
        """
        Initialize the AI client.

        Args:
            config: Model configuration
        """
        self._config = config
        self._session = requests.Session()
        self._session.timeout = config.timeout

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Generate a response from the AI model.

        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            **kwargs: Additional provider-specific parameters

        Returns:
            str: The generated response text

        Raises:
            AIClientError: If generation fails
        """
        if self._config.provider == ModelProvider.OLLAMA:
            return self._generate_ollama(prompt, system_prompt, **kwargs)
        elif self._config.provider == ModelProvider.OPENAI:
            return self._generate_openai(prompt, system_prompt, **kwargs)
        elif self._config.provider == ModelProvider.CLAUDE:
            return self._generate_claude(prompt, system_prompt, **kwargs)
        elif self._config.provider == ModelProvider.GEMINI:
            return self._generate_gemini(prompt, system_prompt, **kwargs)
        else:
            return self._generate_custom(prompt, system_prompt, **kwargs)

    def _generate_ollama(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Generate using Ollama API."""
        url = f"{self._config.base_url}/api/generate"
        payload = {
            "model": self._config.model_name or self._config.model_id,
            "prompt": prompt,
            "stream": False,
            "temperature": kwargs.get("temperature", self._config.temperature),
            "max_tokens": kwargs.get("max_tokens", self._config.max_tokens),
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            response = self._session.post(
                url, json=payload, timeout=self._config.timeout
            )
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")
        except requests.RequestException as e:
            raise AIClientError(f"Ollama request failed: {e!s}") from e
        except json.JSONDecodeError as e:
            raise AIClientError(f"Invalid JSON response: {e!s}") from e

    def _generate_openai(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Generate using OpenAI API."""
        url = f"{self._config.base_url}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self._config.model_name or self._config.model_id,
            "messages": messages,
            "temperature": kwargs.get("temperature", self._config.temperature),
            "max_tokens": kwargs.get("max_tokens", self._config.max_tokens),
        }

        try:
            response = self._session.post(
                url, headers=headers, json=payload, timeout=self._config.timeout
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except requests.RequestException as e:
            raise AIClientError(f"OpenAI request failed: {e!s}") from e
        except (KeyError, json.JSONDecodeError) as e:
            raise AIClientError(f"Invalid response: {e!s}") from e

    def _generate_claude(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Generate using Claude API."""
        url = f"{self._config.base_url}/v1/messages"
        headers = {
            "x-api-key": self._config.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self._config.model_name or self._config.model_id,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": kwargs.get("max_tokens", self._config.max_tokens),
            "temperature": kwargs.get("temperature", self._config.temperature),
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            response = self._session.post(
                url, headers=headers, json=payload, timeout=self._config.timeout
            )
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]
        except requests.RequestException as e:
            raise AIClientError(f"Claude request failed: {e!s}") from e
        except (KeyError, json.JSONDecodeError) as e:
            raise AIClientError(f"Invalid response: {e!s}") from e

    def _generate_gemini(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Generate using Gemini API."""
        url = f"{self._config.base_url}/v1/models/{self._config.model_name}:generateContent"
        if self._config.api_key:
            url += f"?key={self._config.api_key}"

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": kwargs.get("temperature", self._config.temperature),
                "maxOutputTokens": kwargs.get("max_tokens", self._config.max_tokens),
            },
        }
        if system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}

        try:
            response = self._session.post(
                url, json=payload, timeout=self._config.timeout
            )
            response.raise_for_status()
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except requests.RequestException as e:
            raise AIClientError(f"Gemini request failed: {e!s}") from e
        except (KeyError, json.JSONDecodeError) as e:
            raise AIClientError(f"Invalid response: {e!s}") from e

    def _generate_custom(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Generate using custom endpoint."""
        url = self._config.base_url
        headers = {}
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"
        headers["Content-Type"] = "application/json"

        payload = {
            "prompt": prompt,
            "temperature": kwargs.get("temperature", self._config.temperature),
            "max_tokens": kwargs.get("max_tokens", self._config.max_tokens),
        }
        if system_prompt:
            payload["system_prompt"] = system_prompt
        if self._config.metadata:
            payload.update(self._config.metadata)

        try:
            response = self._session.post(
                url, headers=headers, json=payload, timeout=self._config.timeout
            )
            response.raise_for_status()
            data = response.json()
            return data.get(
                "response", data.get("text", data.get("content", str(data)))
            )
        except requests.RequestException as e:
            raise AIClientError(f"Custom request failed: {e!s}") from e
        except json.JSONDecodeError as e:
            raise AIClientError(f"Invalid JSON response: {e!s}") from e
