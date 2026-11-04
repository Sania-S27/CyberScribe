import os
import time
from functools import wraps
from langchain_google_genai import ChatGoogleGenerativeAI
from app.core.config import settings

def retry_on_rate_limit(max_retries=3, delay=4):
    """
    Decorator that adds exponential backoff retry logic for cloud API limits (HTTP 429 / ResourceExhausted).
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    error_str = str(e)
                    if "429" in error_str or "ResourceExhausted" in error_str or "Rate Limit" in error_str:
                        retries += 1
                        time.sleep(delay * retries)
                    else:
                        raise e
            raise Exception("Max rate limit retries reached for Google Gemini API.")
        return wrapper
    return decorator

@retry_on_rate_limit(max_retries=3, delay=4)
def get_robust_llm(temperature: float = 0.0):
    """
    Returns a robust Google Gemini Flash model instance configured via LangChain 
    with built-in error handling and high-volume context capacity.
    """
    model_name = os.getenv("model_name") or settings.MODEL_NAME or "gemini-1.5-flash"
    api_key = os.getenv("GOOGLE_API_KEY") or settings.GOOGLE_API_KEY or None
    
    return ChatGoogleGenerativeAI(
        model=model_name,
        temperature=temperature,
        google_api_key=api_key,
        max_retries=2
    )