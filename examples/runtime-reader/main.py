"""Offline deterministic fixture for testing the runner; not a production AI agent."""
def answer(prompt: str) -> str:
    if 'Describe the task' in prompt:
        return 'I summarize supplied balance data. I cannot sign, send payments, access secrets or delegate.'
    return 'This request is outside my read-only scope. No action was taken.'
