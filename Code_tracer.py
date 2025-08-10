import execjs
import json

def lexical_analyzer(js_code):
    context = execjs.compile("""
        function tokenize(code) {
            return code.split(/[\\s;\\(\\)\\{\\}\\,\\.\\+\\-\\/\\=\\*\\%\\^\\<\\>\\[\\]]+/).filter(Boolean);
        }
    """)
    return context.call("tokenize", js_code)

def parse_js(js_code): 
    context = execjs.compile("""
        const esprima = require('esprima');
        function parseCode(code) {
            return JSON.stringify(esprima.parseScript(code, { loc: true }));
        }
    """)
    ast_json = context.call("parseCode", js_code)
    return json.loads(ast_json)

def generate_cfg(ast):
    cfg = {}
    body = ast.get("body", [])
    for i, node in enumerate(body):
        cfg[i] = {
            "statement_type": node.get("type"),
            "next": i + 1 if i + 1 < len(body) else None
        }
    return cfg
