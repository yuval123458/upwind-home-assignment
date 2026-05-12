from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    anthropic_api_key: str = ""
    safe_browsing_api_key: str = ""
    virustotal_api_key: str = ""
    urlscan_api_key: str = ""
    abuseipdb_api_key: str = ""
    hybrid_analysis_api_key: str = ""

    google_client_id: str = ""

    database_url: str = "sqlite:///./scorer.db"
    env: str = "development"


settings = Settings()
