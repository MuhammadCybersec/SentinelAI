# =============================================================================
# FILE: app/services/ai/model_manager.py
# =============================================================================
# DESCRIPTION: Model Manager for AI services - Manages model configurations
# =============================================================================

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ModelProvider(Enum):
    """Supported AI model providers."""

    OLLAMA = "ollama"
    OPENAI = "openai"
    CLAUDE = "claude"
    GEMINI = "gemini"
    CUSTOM = "custom"


@dataclass
class ModelConfig:
    """
    Configuration for an AI model.

    Attributes:
        model_id: Unique identifier for the model
        provider: The model provider
        api_key: API key for the provider (if required)
        base_url: Base URL for the provider's API
        model_name: Name of the model (e.g., "llama2", "gpt-4")
        temperature: Temperature for generation
        max_tokens: Maximum tokens to generate
        timeout: Request timeout in seconds
        metadata: Additional metadata
    """

    model_id: str
    provider: ModelProvider
    api_key: str | None = None
    base_url: str | None = None
    model_name: str = ""
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: float = 60.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if not self.model_id:
            raise ValueError("model_id cannot be empty")
        if self.temperature < 0 or self.temperature > 2:
            raise ValueError("temperature must be between 0 and 2")
        if self.max_tokens < 1:
            raise ValueError("max_tokens must be greater than 0")
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")


class ModelManager:
    """
    Manager for AI model configurations.

    Features:
        - Register and manage multiple models
        - Set and get active model
        - Thread-safe operations

    Example:
        >>> manager = ModelManager()
        >>> config = ModelConfig(
        ...     model_id="llama2",
        ...     provider=ModelProvider.OLLAMA,
        ...     model_name="llama2:7b",
        ...     base_url="http://localhost:11434",
        ... )
        >>> manager.register_model(config)
        >>> manager.set_active_model("llama2")
        >>> active = manager.get_active_model()
    """

    def __init__(self) -> None:
        """Initialize the ModelManager."""
        self._models: dict[str, ModelConfig] = {}
        self._active_model_id: str | None = None
        self._lock = threading.RLock()

    def register_model(self, config: ModelConfig) -> None:
        """
        Register a model configuration.

        Args:
            config: The model configuration to register

        Raises:
            ValueError: If a model with the same ID already exists
        """
        with self._lock:
            if config.model_id in self._models:
                raise ValueError(f"Model '{config.model_id}' already registered")
            self._models[config.model_id] = config

    def unregister_model(self, model_id: str) -> bool:
        """
        Unregister a model configuration.

        Args:
            model_id: ID of the model to unregister

        Returns:
            bool: True if removed, False if not found

        Raises:
            ValueError: If trying to unregister the active model
        """
        with self._lock:
            if model_id == self._active_model_id:
                raise ValueError(f"Cannot unregister active model '{model_id}'")
            return self._models.pop(model_id, None) is not None

    def set_active_model(self, model_id: str) -> None:
        """
        Set the active model.

        Args:
            model_id: ID of the model to set as active

        Raises:
            ValueError: If the model is not registered
        """
        with self._lock:
            if model_id not in self._models:
                raise ValueError(f"Model '{model_id}' not registered")
            self._active_model_id = model_id

    def set_active_model_config(self, config: ModelConfig) -> None:
        """
        Register and set active model in one operation.

        Args:
            config: The model configuration to set as active
        """
        with self._lock:
            self._models[config.model_id] = config
            self._active_model_id = config.model_id

    def get_active_model(self) -> ModelConfig | None:
        """
        Get the active model configuration.

        Returns:
            Optional[ModelConfig]: The active model config or None
        """
        with self._lock:
            if self._active_model_id is None:
                return None
            return self._models.get(self._active_model_id)

    def get_model(self, model_id: str) -> ModelConfig | None:
        """
        Get a model configuration by ID.

        Args:
            model_id: ID of the model to get

        Returns:
            Optional[ModelConfig]: The model config or None
        """
        with self._lock:
            return self._models.get(model_id)

    def get_all_models(self) -> list[ModelConfig]:
        """
        Get all registered model configurations.

        Returns:
            List[ModelConfig]: List of all model configs
        """
        with self._lock:
            return list(self._models.values())

    def get_active_model_id(self) -> str | None:
        """
        Get the active model ID.

        Returns:
            Optional[str]: The active model ID or None
        """
        with self._lock:
            return self._active_model_id

    def model_exists(self, model_id: str) -> bool:
        """
        Check if a model is registered.

        Args:
            model_id: ID of the model to check

        Returns:
            bool: True if the model exists
        """
        with self._lock:
            return model_id in self._models

    def clear(self) -> None:
        """Clear all registered models."""
        with self._lock:
            self._models.clear()
            self._active_model_id = None

    def get_active_provider(self) -> ModelProvider | None:
        """
        Get the provider of the active model.

        Returns:
            Optional[ModelProvider]: The provider or None
        """
        with self._lock:
            if self._active_model_id is None:
                return None
            model = self._models.get(self._active_model_id)
            return model.provider if model else None
