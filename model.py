from dataclasses import dataclass

@dataclass
class Entry:
    site: str
    username: str
    password: str
    notes: str = ""