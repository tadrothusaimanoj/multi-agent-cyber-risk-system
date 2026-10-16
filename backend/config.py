"""
CyberGuard AI - Central Configuration Module
Defines settings, environment overrides, risk weights, and constants.
"""

from typing import Dict, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable override support."""
    
    # Project Identity
    PROJECT_NAME: str = "CyberGuard AI"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    
    # Server configuration
    API_HOST: str = Field(default="0.0.0.0", alias="HOST")
    API_PORT: int = Field(default=8000, alias="PORT")
    DEBUG: bool = Field(default=False, alias="DEBUG")
    
    # Database configuration (SQLite default, PostgreSQL via DATABASE_URL)
    DATABASE_URL: str = Field(
        default="sqlite:///./data/cyberguard.db",
        alias="DATABASE_URL"
    )
    
    # Random Seed for deterministic synthetic generation and ML
    RANDOM_SEED: int = 42
    
    # Risk Quantification Weights & Constants
    SEVERITY_WEIGHTS: Dict[str, float] = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.45,
        "low": 0.15
    }
    
    EXPOSURE_MULTIPLIERS: Dict[str, float] = {
        "internet_facing": 1.0,
        "dmz": 0.75,
        "internal": 0.40,
        "isolated": 0.15
    }
    
    ASSET_CRITICALITY_MULTIPLIERS: Dict[str, float] = {
        "critical": 1.5,
        "high": 1.25,
        "medium": 1.0,
        "low": 0.75
    }
    
    # Model persistence
    ML_MODEL_PATH: str = "backend/models/exploit_model.joblib"
    
    # Default Monte Carlo simulation iterations for FAIR validation
    FAIR_SIMULATION_RUNS: int = 10000
    
    # Optional external API keys
    NVD_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


# Centralized singleton instance
settings = Settings()
