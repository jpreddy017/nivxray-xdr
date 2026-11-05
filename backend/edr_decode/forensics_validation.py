"""Shared validation before cache access, process launch and worker dispatch."""
import base64
from .recipes import MAX_BYTES,validate_steps
MAX_COMMAND=65536

def validate_request(request):
    if not isinstance(request,dict):raise ValueError('request object required')
    mode=request.get('mode')
    if mode=='command':
        if set(request)-{'mode','command_line','selected_payload'}:raise ValueError('unknown fields')
        text=request.get('command_line')
        if not isinstance(text,str) or not text.strip() or '\x00' in text or len(text.encode('utf-8'))>MAX_COMMAND:
            raise ValueError('invalid command')
        selected=request.get('selected_payload')
        if selected is not None and (not isinstance(selected,str) or not selected or selected not in text):
            raise ValueError('invalid selected payload')
    elif mode=='recipe':
        if set(request)!={'mode','input_base64','steps'}:raise ValueError('invalid recipe fields')
        encoded=request['input_base64']
        if not isinstance(encoded,str) or len(encoded)>1398104:raise ValueError('invalid recipe bytes')
        data=base64.b64decode(encoded,validate=True)
        if len(data)>MAX_BYTES or base64.b64encode(data).decode()!=encoded:raise ValueError('invalid recipe bytes')
        validate_steps(request['steps'])
    else:raise ValueError('unsupported mode')
