import os
import subprocess


class Commands:
    def __init__(self, ai):
        self.ai = ai
        lucy_dir = os.path.dirname(os.path.abspath(__file__))
        self.base_dir = os.path.dirname(lucy_dir)
        self.creations_dir = os.path.join(
            self.base_dir,
            "AI_creations"
        )

        os.makedirs(self.creations_dir, exist_ok=True)


    def get_file_path(self, fname):
        fname = os.path.basename(fname)
        return os.path.join(
            self.creations_dir,
            fname
        )


    def do_command(self, s):
        parts = s.split("|")
        if len(parts) < 2:
            return "Error: Missing fields in command."
        try:
            action = parts[0].split(":", 1)[1].strip().lower()
            fname = parts[1].split(":", 1)[1].strip()

            if len(parts) > 2:
                content = parts[2].split(":", 1)[1].strip()
            else:
                content = ""
        except IndexError:
            return "Error: Invalid command format."
        file_path = self.get_file_path(fname)

        if action in ("write", "create"):
            try:
                with open(
                    file_path,
                    "w",
                    encoding="utf-8"
                ) as f:
                    f.write(content)
                return f"File {fname} created successfully."
            except Exception as e:
                return (
                    f"Error: {e}. "
                    f"Could not create or write file {fname}."
                )
            
        elif action == "open":
            try:
                if not os.path.exists(file_path):
                    return f"File {fname} doesn't exist."
                subprocess.run(["open", file_path])
                return f"File {fname} opened successfully."
            except Exception as e:
                return f"Error: {e}. Could not open file {fname}."
            
        elif action == "delete":
            try:
                os.remove(file_path)

                return f"File {fname} deleted successfully."
            except FileNotFoundError:
                return f"File {fname} doesn't exist."
            except Exception as e:
                return f"Error: {e}. Could not delete file {fname}."
            
        elif action == "summarize":
            try:
                return self.ai.summarize_nids()
            except Exception as e:
                return f"Error summarizing NIDS: {e}"

        elif action == "suggest":
            try:
                return self.ai.suggest_rules()
            except Exception as e:
                return f"Error suggesting rules: {e}"
            
        elif action == "python3":
            try:
                if not os.path.exists(file_path):
                    return f"File {fname} doesn't exist."
                process = subprocess.run(
                    ["python3", file_path],
                    capture_output=True,
                    text=True,
                    cwd=self.creations_dir
                )
                if process.returncode != 0:
                    return (
                        f"Error executing {fname}: "
                        f"{process.stderr.strip() or 'Unknown error'}"
                    )
                return f"File {fname} executed successfully."
            except Exception as e:
                return f"Error {e}. Could not execute file {fname}."
            
        else:
            return f"Error: Unknown action '{action}'."