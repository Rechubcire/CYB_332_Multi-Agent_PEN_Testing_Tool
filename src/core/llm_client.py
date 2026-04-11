"""
This is the main pipeline for all agents. All agents
will use call_llm(), they will NOT directly call the
model in use
"""

import os
import json
from datetime import datetime, timezone
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

load_dotenv()

def get_llm_model():
    """
    Reads LLM_PROVIDER from .env and 
    returns the correct LangChain chat model
    """
    provider = os.getenv("LLM_PROVIDER", "groq") # Second parameter is the default provider

    
    if provider == "anthropic":
        return ChatAnthropic(
            model="claude-sonnet-4-5",
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            max_tokens=1500
        )

    elif provider == "groq":
        return ChatGroq(
            model="llama-3.3-70b-versatile",
            api_key=os.getenv("GROQ_API_KEY"),
            max_tokens=1500
        )

    else:
        raise ValueError(f"Unknown LLM Provider: '{provider}'. Please use Anthropic or Groq")


def call_llm(system_prompt: str, user_content: str, agent_name="unknown") -> str:
    """
    This is the entry point for all agents into the llm
    uses the provider selected from the user's .env file
    """

    model = get_llm_model()

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_content)
    ]

    response = model.invoke(messages)

    raw_text = response.content

    
    

    # Clean the raw text from the LLM
    cleaned = raw_text.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned[7:] # Remove the opening JSON fence
    if cleaned.startswith("```"):
        cleaned = cleaned[3:] # Remove the opening JSON fence
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3] # Remove the closing JSON fence

    cleaned = cleaned.strip()


    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        log_llm_call(agent_name, system_prompt, user_content, raw_text, None)
        raise

    log_llm_call(agent_name, system_prompt, user_content, raw_text, parsed)

    return parsed

def log_llm_call(agent_name: str, system_prompt: str, user_content: str, raw_text: str, parsed: str) -> None:
    """
    Appends the returned JSON output from the LLM
    as parsed text to the run.log file
    """
    # Make sure the output dir exists
    os.makedirs("output", exist_ok=True)

    entry = { 
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": agent_name,
        "provider": os.getenv("LLM_PROVIDER", "unknown"),
        "system_prompt": system_prompt,
        "user_content": user_content,
        "raw_response": raw_text,
        "parsed_output": parsed,
        "success": (not parsed == None)
    }


    # Add to LLM Call log
    with open("output/run.log", "a") as file:
        file.write(json.dumps(entry) + "\n")


def load_prompt(filename: str) -> str:
    """
    Loads prompt file
    """
    path = os.path.join("prompts", filename)
    
    try:
        with open(path, "r") as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: the file {path} was not found.")
        raise