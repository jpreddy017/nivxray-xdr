"""Constrained constant AST pass using the existing PowerShell tokenizer.

Only a small typed expression grammar and straight-line local assignments are
interpreted. Calls, scopes, interpolation, control flow and side effects are
refused. This is not a full PowerShell parser or an execution environment.
"""
import re
import base64
from v2.semantic.ps_ast import tokenize, Token, TOK_OPERATOR, TOK_EOF, TOK_STRING, TOK_NUMBER, TOK_VARIABLE, TOK_TYPECAST

MAX_TOKENS=2048
MAX_ITEMS=512
MAX_CHARS=131072
MAX_NODES=1024
MAX_DEPTH=16
class Unsupported(ValueError): pass


def bounded(value):
    if isinstance(value,int) and not -2147483648 <= value <= 2147483647:
        raise Unsupported('Integer range exceeded')
    if isinstance(value,bytes) and len(value)>MAX_CHARS:raise Unsupported('Byte output limit exceeded')
    if isinstance(value,str) and (len(value.encode('utf-8'))>MAX_CHARS or any(0xD800<=ord(c)<=0xDFFF for c in value)):
        raise Unsupported('String limit or unsupported surrogate')
    if isinstance(value,list):
        if len(value)>MAX_ITEMS: raise Unsupported('Array item limit exceeded')
        for item in value:
            if isinstance(item,list): raise Unsupported('Nested arrays unsupported')
            bounded(item)
    return value


def lex(source):
    if len(source.encode('utf-8'))>16384 or any(c in source for c in ('`','#','@"',"@'")):
        raise Unsupported('Unsupported lexical construct')
    result=[];pos=0
    for t in tokenize(source):
        gap=source[pos:t.start]
        # Existing tokenizer intentionally skips unknown characters. Refuse
        # every such gap, except the arithmetic minus operator modeled here.
        if gap.strip():
            if gap.strip()=='-': result.append(Token(TOK_OPERATOR,'-',pos,t.start))
            else: raise Unsupported('Unrecognized token')
        if t.kind==TOK_STRING and t.quote=="'" and "''" in source[t.start+1:t.end-1]:
            raise Unsupported('Escaped quote grammar remains unsupported')
        if t.kind==TOK_STRING and (t.end<=t.start+1 or source[t.end-1]!=t.quote):
            raise Unsupported('Unterminated string')
        if t.kind!=TOK_EOF:result.append(t)
        pos=t.end
    if len(result)>MAX_TOKENS:raise Unsupported('Token limit exceeded')
    return result


class Parser:
    def __init__(self,tokens):self.tokens=tokens;self.i=0;self.nodes=0
    def peek(self):return self.tokens[self.i].value.lower() if self.i<len(self.tokens) else ''
    def take(self):
        if self.i>=len(self.tokens):raise Unsupported('Incomplete expression')
        t=self.tokens[self.i];self.i+=1;return t
    def require(self,value):
        if self.peek()!=value:raise Unsupported('Unsupported expression grammar')
        self.take()
    def node(self,*parts):
        self.nodes+=1
        if self.nodes>MAX_NODES:raise Unsupported('AST node limit exceeded')
        return parts
    def expression(self,minimum=0,depth=0):
        if depth>MAX_DEPTH:raise Unsupported('AST depth limit exceeded')
        t=self.take();v=t.value.lower()
        if v in ('(','@('):
            left=self.expression(0,depth+1);self.require(')')
            if v=='@(':left=self.node('array_wrap',left)
        elif v=='-join':left=self.node('unary_join',self.expression(6,depth+1))
        elif t.kind==TOK_STRING:
            raw=t.value
            # Tokenizer decodes literals; check original quote metadata.
            if t.quote=='"' and '$' in raw:raise Unsupported('Interpolation unsupported')
            left=self.node('literal',raw)
        elif t.kind==TOK_NUMBER:
            if not re.fullmatch(r'-?(?:0x[0-9a-f]+|\d+)',v):raise Unsupported('Only integer literals supported')
            left=self.node('literal',bounded(int(v,16 if '0x' in v else 10)))
        elif t.kind==TOK_VARIABLE:
            if not re.fullmatch(r'[A-Za-z_]\w*',v):raise Unsupported('Scoped variable unsupported')
            left=self.node('variable',v)
        elif t.kind==TOK_TYPECAST and v in ('convert','system.convert'):
            self.require('::');self.require('frombase64string');self.require('(')
            argument=self.expression(0,depth+1);self.require(')');left=self.node('base64',argument)
        elif t.kind==TOK_TYPECAST and v in ('text.encoding','system.text.encoding'):
            self.require('::');member=self.take().value.lower()
            if not re.fullmatch(r'(utf8|unicode|bigendianunicode|ascii)\.getstring',member):raise Unsupported('Encoding unsupported')
            encoding=member.split('.')[0]
            self.require('(');argument=self.expression(0,depth+1);self.require(')')
            left=self.node('decode_text',encoding,argument)
        elif t.kind==TOK_TYPECAST and v in ('char','char[]','byte','byte[]','int'):
            left=self.node('cast',v,self.expression(6,depth+1))
        else:raise Unsupported('Unsupported atom')
        precedence={',':1,'-f':2,'-join':2,'-bxor':3,'-band':3,'-bor':3,'+':4,'-':4,'*':5,'%':5}
        while self.i<len(self.tokens):
            op=self.peek()
            if op=='|' and minimum==0:
                self.take()
                if self.peek() not in ('foreach-object','%'):raise Unsupported('Only pure ForEach-Object maps supported')
                self.take();self.require('{');body=self.expression(0,depth+1);self.require('}')
                left=self.node('map',left,body);continue
            rank=precedence.get(op,-1)
            if rank<minimum:break
            self.take();right=self.expression(1 if op=='-f' else rank+1,depth+1)
            left=self.node('binary',op,left,right)
        return left


def safe_join(values,separator=''):
    strings=[str(v) for v in values]
    size=sum(len(v.encode('utf-8')) for v in strings)+max(0,len(strings)-1)*len(separator.encode('utf-8'))
    if size>MAX_CHARS:raise Unsupported('String expansion limit exceeded')
    return separator.join(strings)


def evaluate(node,env,depth=0,steps=None):
    if steps is None:steps=[0]
    steps[0]+=1
    if steps[0]>16384:raise Unsupported('Symbolic operation budget exceeded')
    if depth>MAX_DEPTH:raise Unsupported('Evaluation depth limit exceeded')
    kind=node[0]
    if kind=='literal':return bounded(node[1])
    if kind=='base64':
        value=evaluate(node[1],env,depth+1,steps)
        if not isinstance(value,str):raise Unsupported('Base64 requires a constant string')
        return bounded(base64.b64decode(value,validate=True))
    if kind=='decode_text':
        value=evaluate(node[2],env,depth+1,steps)
        if not isinstance(value,bytes):raise Unsupported('GetString requires constant bytes')
        encoding={'utf8':'utf-8','unicode':'utf-16-le','bigendianunicode':'utf-16-be','ascii':'ascii'}[node[1]]
        return bounded(value.decode(encoding,errors='strict'))
    if kind=='variable':
        if node[1] not in env:raise Unsupported('Unknown variable')
        return env[node[1]]
    if kind=='array_wrap':
        v=evaluate(node[1],env,depth+1,steps);return bounded(v if isinstance(v,list) else [v])
    if kind=='cast':
        typ=node[1];v=evaluate(node[2],env,depth+1,steps)
        def convert(n):
            if not isinstance(n,int):raise Unsupported('Only integer casts supported')
            if typ.startswith('char'):
                if not 0<=n<=65535 or 0xD800<=n<=0xDFFF:raise Unsupported('Invalid character code')
                return chr(n)
            if typ.startswith('byte') and not 0<=n<=255:raise Unsupported('Invalid byte')
            return bounded(n)
        if typ.endswith('[]'):
            return bounded([convert(n) for n in (v if isinstance(v,list) else [v])])
        return convert(v)
    if kind=='unary_join':
        v=evaluate(node[1],env,depth+1,steps)
        if not isinstance(v,(str,list)):raise Unsupported('Join type unsupported')
        return bounded(safe_join(v) if isinstance(v,list) else v)
    if kind=='map':
        source=evaluate(node[1],env,depth+1,steps)
        if not isinstance(source,list):raise Unsupported('Map requires constant array')
        return bounded([evaluate(node[2],{**env,'_':x},depth+1,steps) for x in source])
    if kind!='binary':raise Unsupported('Unknown AST node')
    op=node[1];a=evaluate(node[2],env,depth+1,steps);b=evaluate(node[3],env,depth+1,steps)
    if op==',':return bounded((a if isinstance(a,list) else [a])+[b])
    if op=='-join':
        if not isinstance(a,(list,str)) or not isinstance(b,str):raise Unsupported('Join type unsupported')
        return bounded(safe_join(a,b) if isinstance(a,list) else a)
    if op=='-f':
        if not isinstance(a,str):raise Unsupported('Format requires literal string')
        args=b if isinstance(b,list) else [b]
        if '"' in a or any(isinstance(x,str) and '"' in x for x in args):raise Unsupported('Mixed-quote formatting remains unsupported')
        if any(not isinstance(x,str) for x in args):raise Unsupported('Culture-dependent formatting refused')
        if re.sub(r'\{\d+\}','',a).find('{')>=0 or '}' in re.sub(r'\{\d+\}','',a):raise Unsupported('Format grammar unsupported')
        def replace(m):
            index=int(m.group()[1:-1])
            if index>=len(args):raise Unsupported('Format index outside arguments')
            return args[index]
        matches=list(re.finditer(r'\{\d+\}',a))
        if len(a.encode())+sum(len(replace(m).encode())-len(m.group()) for m in matches)>MAX_CHARS:raise Unsupported('Format expansion limit exceeded')
        return bounded(re.sub(r'\{\d+\}',replace,a))
    if op=='+' and isinstance(a,str) and isinstance(b,str):return bounded(safe_join([a,b]))
    if not isinstance(a,int) or not isinstance(b,int):raise Unsupported('Mixed or collection arithmetic refused')
    if op=='+':v=a+b
    elif op=='-':v=a-b
    elif op=='*':v=a*b
    elif op=='%' and a>=0 and b>0:v=a%b
    elif op=='-bxor':v=a^b
    elif op=='-band':v=a&b
    elif op=='-bor':v=a|b
    else:raise Unsupported('Arithmetic grammar unsupported')
    return bounded(v)


def operations(node):
    """Post-order operator recipe for this bounded constant expression AST."""
    result=[]
    def walk(n):
        if n[0] in ('literal','variable'):return
        for child in n[1:]:
            if isinstance(child,tuple):walk(child)
        name=(n[1] if n[0]=='binary' else 'cast:'+n[1] if n[0]=='cast' else 'decode:'+n[1] if n[0]=='decode_text' else n[0])
        result.append(name)
    walk(node)
    return result


def render(value):
    bounded(value)
    if isinstance(value,str):
        if len(value.encode())+value.count("'")+2>MAX_CHARS:raise Unsupported('Literal rendering limit exceeded')
        return "'"+value.replace("'","''")+"'"
    if isinstance(value,int):return str(value)
    if isinstance(value,list):return safe_join(['@(',safe_join((render(x) for x in value),','),')'])
    raise Unsupported('Binary value remains an embedded payload')


def reconstruct(source):
    """Return a complete supported program rewrite and exact expression spans.

    Assignments are retained in place, not discarded as if side effects vanished.
    Unknown statements invalidate the entire environment, preventing dataflow
    across branches, functions, external calls or scope mutation.
    """
    try:
        tokens=lex(source)
        parser=Parser(tokens);env={};edits=[];statements=0;steps=[0]
        while parser.i<len(tokens):
            if parser.peek()==';':parser.take();continue
            statements+=1
            if statements>32:raise Unsupported('Statement limit exceeded')
            first=tokens[parser.i];assignment=False
            if first.kind==TOK_VARIABLE and parser.i+1<len(tokens) and tokens[parser.i+1].value=='=':
                name=first.value.lower()
                if not re.fullmatch(r'[a-z][a-z0-9_]*',name) or name.startswith('ps') or name in {'true','false','null','args','input','pshome','pwd','error','host','executioncontext','lastexitcode','pid','home','profile','myinvocation','matches','foreach','switch','this','nestedpromptlevel','sender','shellid','stacktrace','islinux','ismacos','iswindows','iscoreclr','event','eventargs','eventsubscriber','enabledexperimentalfeatures','consolefilename'}:raise Unsupported('Automatic/scoped variable refused')
                parser.i+=2;assignment=True
            elif first.value.lower() in ('write-output','write-host','iex','invoke-expression'):
                parser.take()
            start=parser.i
            tree=parser.expression();value=evaluate(tree,env,steps=steps)
            if parser.i<len(tokens) and parser.peek() not in (';','\n','\r'):
                raise Unsupported('Trailing unsupported statement')
            if assignment:env[name]=value
            if start==parser.i:raise Unsupported('Empty expression')
            lo,hi=tokens[start].start,tokens[parser.i-1].end
            replacement=render(value)
            if tree[0]!='literal' and source[lo:hi]!=replacement:edits.append({'start':lo,'end':hi,'replacement':replacement,'operations':operations(tree)})
            if parser.i<len(tokens):parser.take()
        if len(source.encode())+sum(len(e['replacement'].encode())-len(source[e['start']:e['end']].encode()) for e in edits)>MAX_CHARS:raise Unsupported('Program output limit exceeded')
        output=source
        for e in reversed(edits):output=output[:e['start']]+e['replacement']+output[e['end']:]
        bounded(output)
        return output,edits
    except (Unsupported,ValueError,IndexError,RecursionError):return None


def unresolved(source):
    # Only the fully validated restricted program can establish constant scope.
    return reconstruct(source) is None
