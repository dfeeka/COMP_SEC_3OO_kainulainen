import argparse
import sys
import tkinter as tk
from ui import VaultApp


# Main used to launch the program
def main():
    parser = argparse.ArgumentParser(description="Password Manager")
    parser.add_argument("--headless-test", action="store_true", help="Run basic headless tests and exit")
    args = parser.parse_args()
    if args.headless_test:
        print("Headless tests not implemented.")
        sys.exit(0)
    root = tk.Tk()
    VaultApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
