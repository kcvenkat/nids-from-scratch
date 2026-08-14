# ai.py
from google import genai
from google.genai import types
import os
from dotenv import load_dotenv
from nids import summarize_prompt, suggest_prompt

class AI:
    def __init__(self, model="gemini-2.5-flash"):
        lucy_dir = os.path.dirname(os.path.abspath(__file__))
        root_dir = os.path.dirname(lucy_dir)
        env_path = os.path.join(root_dir, ".env")

        load_dotenv(env_path)

        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY (or GOOGLE_API_KEY) not set in environment or .env file")

        self.client = genai.Client(api_key=self.api_key)

        base_dir = os.path.dirname(os.path.abspath(__file__))

        system_prompt_path = os.path.join(
            base_dir,
            "system_prompt.txt"
        )

        if not os.path.exists(system_prompt_path):
            raise FileNotFoundError(
                f"system_prompt.txt is missing at: {system_prompt_path}"
            )

        self.system_instruction = self.load_system_prompt(
            system_prompt_path
        )

        self.model = model

        try:
            self.chat = self.client.chats.create(
                model=self.model,
                config=types.GenerateContentConfig(system_instruction=self.system_instruction)
            )
        except Exception as e:
            raise RuntimeError(f"Failed to create genai chat session: {e}")

    def load_system_prompt(self, filename):
            with open(filename, "r", encoding="utf-8") as file:
                return file.read()

    def process(self, user_input):
        try:
            response = self.chat.send_message(user_input)
        except Exception as e:
            print(f"Error sending message to model: {e}")
            return ""

        if hasattr(response, "text"):
            return response.text
        try:
            if hasattr(response, "candidates") and response.candidates:
                c = response.candidates[0]
                return getattr(c, "content", getattr(c, "output", str(c)))
            if hasattr(response, "last") and response.last and hasattr(response.last, "content"):
                return response.last.content
        except Exception:
            pass

        return str(response)

    def summarize_nids(self):
        prompt = summarize_prompt()

        response = self.process(prompt)

        if not response:
            return "Error: AI returned no summary."

        with open("nids_summary.txt", "w", encoding="utf-8") as f:
            f.write(response)

        return "NIDS summary generated successfully in nids_summary.txt."

    def suggest_rules(self):
        prompt = suggest_prompt()
        response = self.process(prompt)

        if not response:
            return "Error: AI returned no rules."

        with open("rules.txt", "a", encoding="utf-8") as f:
            f.write("\n" + response)

        return "New detection rules generated successfully in rules.txt.\n Note that the AI may generate erroneous rules. Please review the generated rules before using them in a production environment."