"""
This is the main pipeline for all agents. All agents
will use call_llm(), they will NOT directly call the
model in use
"""

import os
import json
import anthropic
from groq import Groq
from datetime import datetime, timezone

def call_llm(system_prompt: str, user_content: str, max_tokens=1500, agent_name="unknown") -> str:
    """
    This is the entry point for all agents into the llm
    uses the provider selected from the user's .env file
    """

    provider = os.getenv("LLM_PROVIDER", "groq") # Second parameter is the default provider

    # Route to the provider specified in .env
    # Other providers can also be added but we
    # will only use Anthropic and Groq
    if provider == "anthropic":
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        response = client.messages.create(
            model = 'claude-sonnet-4-5',
            max_tokens = max_tokens,
            system = system_prompt,
            messages = [{ "role": "user", "content": user_content}]
        )

        raw_text = response.content[0].text

    elif provider == "groq":
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages= [
                { "role": "system", "content": system_prompt},
                { "role": "user", "content": user_content}
            ],
            max_tokens= max_tokens
        )

        raw_text = response.choices[0].message.content

    else:
        raise ValueError(f"Unknown LLM Provider: '{provider}'. Please use Anthropic or Groq")
    

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
    except json.JSONDecodeError as e:
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
        "user_content": user_content,
        "system_prompt": system_prompt,
        "raw_response": raw_text,
        "parsed_output": parsed,
        "success": (not parsed == None)
    }

    with open("output/run.log", "a") as file:
        file.write(json.dumps(entry))


def load_prompt(filename: str) -> str:
    path = os.path.join("prompts", filename)
    
    try:
        with open(path, "r") as file:
            prompt = file.read()
    except FileNotFoundError:
        print(f"Error: the file {path} was not found.")

    return prompt