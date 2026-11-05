from .forensics_validation import validate_request
"""EDR-owned static analysis dispatch; called only inside the isolated worker."""
import base64
import hashlib
from .recipes import run_recipe
from .discovery import discover
from .command_layers import recover_layers

MAX_COMMAND = 65536


def analyze_request(request):
    validate_request(request)
    mode = request.get('mode')
    if mode == 'command':
        if set(request) - {'mode', 'command_line', 'selected_payload'}:
            raise ValueError('unknown command arguments')
        text = request.get('command_line')
        if (not isinstance(text, str) or not text.strip() or '\x00' in text
                or len(text.encode('utf-8')) > MAX_COMMAND):
            raise ValueError('invalid command input')
        selected = request.get('selected_payload')
        if selected is not None and (not isinstance(selected,str) or not selected or selected not in text):
            raise ValueError('selected payload is not in original evidence')
        import operations
        import ops_extended
        from command_analyzer import analyze_command
        return {'schema_version':'edr-forensics-v1', 'mode':mode,
                'input_sha256':hashlib.sha256(text.encode('utf-8')).hexdigest(),
                'analysis':analyze_command(text, force_decode_span=selected),
                'recovered_layers':recover_layers(selected if selected is not None else text),
                'layer_candidates':discover((selected if selected is not None else text).encode('utf-8')),
                'candidate_scope':'selected_payload' if selected is not None else 'whole_input',
                'executed':False, 'intelligence_status':'not_queried'}
    if mode == 'recipe':
        if set(request) != {'mode','input_base64','steps'}:
            raise ValueError('invalid recipe arguments')
        encoded = request['input_base64']
        if not isinstance(encoded,str) or len(encoded) > 1398104:
            raise ValueError('invalid recipe input')
        data=base64.b64decode(encoded,validate=True)
        return {'schema_version':'edr-forensics-v1','mode':mode,
                'recipe_result':run_recipe(data,request['steps']),
                'executed':False,'intelligence_status':'not_queried'}
    raise ValueError('unsupported analysis mode')
