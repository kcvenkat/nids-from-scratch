from .speech import Speech
from .ai import AI
from .commands import Commands
import pyfiglet
from rich.console import Console
import readchar

console = Console()
banner = pyfiglet.figlet_format("L.U.C.Y - NIDS", font="slant")
console.print(banner, style="bold rgb(85,0,130)")

ai = AI()
speech = Speech()
commands = Commands(ai)

def run_voice_assistant():
    try:
        while True:
            console.print("[bold purple]Listening...[/bold purple]")
            user_input = speech.capture()
            if not user_input.strip():
                continue

            console.print("You said:", user_input)
            print()
            if user_input.lower() in ("bye", "goodbye", "exit", "quit"):
                break

            response = ai.process(user_input)
            if "Action:" in response and "|" in response:
                cmd_return = commands.do_command(response)
                console.print(cmd_return)
                speech.speak(cmd_return)
            else:
                console.print(response)
                speech.speak(response)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

def run_chatbot():
    try:
        while True:
            user_input = input("Prompt: ").strip()
            if not user_input:
                continue

            if user_input.lower() in ("bye", "goodbye", "exit", "quit"):
                break

            response = ai.process(user_input)
            if "Action:" in response and "|" in response:
                cmd_return = commands.do_command(response)
                print(cmd_return)
                print()
            else:
                print(response)
                print()

    except Exception as e:
        print(f"Error: {e}")

def select_mode():
    while True:
        print("\nChoose an assistant mode:")
        print("  1) Voice assistant")
        print("  2) Chatbot")
        print("  q) Quit")

        console.print("Press 1, 2, or q: ", end="")
        choice = readchar.readkey()

        print(choice)
        print()
        choice = choice.strip().lower()

        if choice == "1":
            return "voice"
        if choice == "2":
            return "chat"
        if choice in ("q", "quit", "exit"):
            return "quit"

        print("\nInvalid selection. Please choose 1, 2, or q.")


def run_assistant():
    mode = select_mode()
    if mode == "voice":
        run_voice_assistant()
    elif mode == "chat":
        run_chatbot()
    else:
        print("Goodbye.")