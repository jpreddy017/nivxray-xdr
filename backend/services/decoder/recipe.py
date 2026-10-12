"""Existing legacy recipe contract, with a single shared worker budget."""
from .isolated import entry
from .resource_limits import DecodeLimitExceeded

@entry()
def replay(input_text, steps):
    from operations import run_operation
    if len(steps) > 32:
        raise DecodeLimitExceeded('Recipe step limit exceeded')
    current, steps_output, errors = input_text, [], []
    for i, step in enumerate(steps):
        try:
            current = run_operation(step['op'], current, step.get('args') or {})
            steps_output.append({'index':i, 'op':step['op'], 'output_preview':current[:400], 'output_length':len(current)})
        except Exception as exc:
            errors.append({'index':str(i), 'op':step['op'], 'error':str(exc)})
            steps_output.append({'index':i, 'op':step['op'], 'error':str(exc)})
            break
    return current, steps_output, errors
