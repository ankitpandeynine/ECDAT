"""Multi-file source analysis with Python AST alias and constant resolution."""
import ast
import hashlib
import json
from pathlib import PurePosixPath
from .polyglot_scanner import scan_polyglot_code

EXTENSIONS = {
    '.py': 'python',
    '.java': 'java',
    '.c': 'c_cpp',
    '.h': 'c_cpp',
    '.cpp': 'c_cpp',
    '.hpp': 'c_cpp',
    '.go': 'golang',
    '.js': 'javascript',
    '.ts': 'javascript',
    '.jsx': 'javascript',
    '.tsx': 'javascript',
    '.rs': 'rust',
}
LANGUAGES = {'python', 'java', 'c_cpp', 'golang', 'javascript', 'rust'}

MANIFEST_NAMES = {
    'requirements.txt', 'pyproject.toml', 'poetry.lock',
    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'pom.xml', 'build.gradle', 'gradle.lockfile',
    'go.mod', 'go.sum',
    'cargo.toml', 'cargo.lock',
}


def is_manifest_file(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name in MANIFEST_NAMES or name.endswith('.requirements.txt') or name.endswith('.gradle')


class Resolve(ast.NodeTransformer):
    def __init__(self, imported_constants=None):
        self.aliases = {}
        self.constants = dict(imported_constants or {})

    def visit_Import(self, node):
        for entry in node.names:
            self.aliases[entry.asname or entry.name.split('.')[0]] = entry.name if entry.asname else entry.name.split('.')[0]
        return node

    def visit_ImportFrom(self, node):
        for entry in node.names:
            self.aliases[entry.asname or entry.name] = f'{node.module}.{entry.name}'
        return node

    def visit_Assign(self, node):
        node = self.generic_visit(node)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.constants.pop(target.id, None)
                self.aliases.pop(target.id, None)
                if isinstance(node.value, ast.Constant):
                    self.constants[target.id] = node.value.value
        return node

    def visit_Name(self, node):
        if not isinstance(node.ctx, ast.Load):
            return node
        if node.id in self.constants:
            return ast.copy_location(ast.Constant(self.constants[node.id]), node)
        if node.id in self.aliases:
            qualified = self.aliases[node.id]
            if qualified in self.constants:
                return ast.copy_location(ast.Constant(self.constants[qualified]), node)
            return ast.copy_location(ast.parse(qualified, mode='eval').body, node)
        return node

    def visit_Attribute(self, node):
        node = self.generic_visit(node)
        key = ast.unparse(node)
        if key in self.constants:
            return ast.copy_location(ast.Constant(self.constants[key]), node)
        return node

    def visit_FunctionDef(self, node):
        old_constants, old_aliases = self.constants.copy(), self.aliases.copy()
        args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        for arg in args + [a for a in (node.args.vararg, node.args.kwarg) if a]:
            self.constants.pop(arg.arg, None)
            self.aliases.pop(arg.arg, None)
        node = self.generic_visit(node)
        self.constants, self.aliases = old_constants, old_aliases
        return node

    visit_AsyncFunctionDef = visit_FunctionDef


def python_findings(source, constants):
    from .ast_scanner import CryptoASTVisitor
    tree = ast.parse(source)
    tree = Resolve(constants).visit(tree)
    ast.fix_missing_locations(tree)
    visitor = CryptoASTVisitor(source.splitlines())
    visitor.visit(tree)
    return visitor.findings


def scan_sources(files, deep_scan: bool = True):

    from .dependency_scanner import get_dependency_scanner
    from .treesitter_scanner import get_treesitter_scanner

    dep_scanner = get_dependency_scanner()
    ts_scanner = get_treesitter_scanner()

    findings, coverage, dependencies = [], [], []
    call_graph, observations = [], []
    constants = {}

    # Pass 1: Resolve module-level direct constants across Python modules
    for file in files:
        if file['path'].endswith('.py'):
            try:
                module = file['path'][:-3].replace('/', '.').replace('\\', '.')
                for node in ast.parse(file['content']).body:
                    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                constants[f'{module}.{target.id}'] = node.value.value
                                constants[target.id] = node.value.value
            except SyntaxError:
                pass

    # Pass 2: Multi-hop cross-file import chaining (e.g. config -> auth -> crypto)
    for _ in range(3):
        for file in files:
            if file['path'].endswith('.py'):
                try:
                    curr_module = file['path'][:-3].replace('/', '.').replace('\\', '.')
                    for node in ast.parse(file['content']).body:
                        if isinstance(node, ast.ImportFrom) and node.module:
                            for alias in node.names:
                                src_key = f"{node.module}.{alias.name}"
                                if src_key in constants:
                                    val = constants[src_key]
                                    constants[f"{curr_module}.{alias.asname or alias.name}"] = val
                                    constants[alias.asname or alias.name] = val
                        elif isinstance(node, ast.Assign):
                            if isinstance(node.value, ast.Name) and node.value.id in constants:
                                val = constants[node.value.id]
                                for target in node.targets:
                                    if isinstance(target, ast.Name):
                                        constants[f"{curr_module}.{target.id}"] = val
                                        constants[target.id] = val
                except SyntaxError:
                    pass

    # Process files
    for file in files:
        path, source = file['path'], file['content']
        lang = file.get('language') or EXTENSIONS.get(PurePosixPath(path).suffix.lower())

        # Check if manifest or lockfile
        if is_manifest_file(path):
            try:
                dep_res = dep_scanner.scan_manifest_or_lockfile(path, source)
                for d in dep_res['dependencies']:
                    # Maintain legacy fields for compatibility with existing tests
                    entry = dict(d, file=path)
                    if 'requirement' not in entry and 'version' in entry:
                        entry['requirement'] = f"{d['name']}=={d['version']}"
                    dependencies.append(entry)
                coverage.append({'file': path, 'status': 'inventory', 'engine': 'manifest'})
            except Exception as e:
                coverage.append({'file': path, 'status': 'error', 'error': str(e)})
            continue

        if lang not in LANGUAGES:
            coverage.append({'file': path, 'status': 'unsupported', 'engine': None})
            continue

        try:
            # Deep Tree-sitter scan if available
            ts_res = None
            if deep_scan and ts_scanner.is_available(lang):
                ts_res = ts_scanner.parse_and_scan(source, lang, file_path=path, external_constants=constants)
                if ts_res.get('status') == 'success':
                    observations.extend(ts_res.get('observations', []))
                    call_graph.extend(ts_res.get('call_graph', []))

            if lang == 'python':
                found = python_findings(source, constants)
                engine = 'python-ast'
            else:
                found = scan_polyglot_code(source, lang)['findings']
                engine = 'regex-heuristic'

            if ts_res and ts_res.get('status') == 'success':
                for ts_f in ts_res.get('findings', []):
                    line_matches = [f for f in found if f.get('line') == ts_f.get('line')]
                    if not line_matches:
                        found.append(ts_f)
                    else:
                        shares_family = any(
                            f.get('primitive', '').split('-')[0] == ts_f.get('primitive', '').split('-')[0]
                            or f.get('primitive', '') == ts_f.get('algorithm', '')
                            for f in line_matches
                        )
                        if not shares_family:
                            found.append(ts_f)


            coverage.append({'file': path, 'language': lang, 'status': 'scanned', 'engine': engine})
            for finding in found:
                finding.setdefault('file', path)
                finding.setdefault('language', lang)
                finding.setdefault('engine', engine)
                finding.setdefault('confidence', 'medium' if lang == 'python' else 'low')
                finding.setdefault('source_hash', hashlib.sha256(source.encode()).hexdigest())
                finding.setdefault('actual_use', True)
                findings.append(finding)

        except SyntaxError as exc:
            coverage.append({'file': path, 'status': 'error', 'engine': 'python-ast', 'error': str(exc)})


    # Construct normalized ECDAT V4 Evidence items
    from .evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, Provenance
    evidence_list = []

    # Map dependencies as E2 declared dependencies
    for dep in dependencies:
        dep_name = dep.get('name') or dep.get('requirement', '').split(';')[0].split('>=')[0].split('==')[0].strip()
        ev = Evidence(
            state=EvidenceState.MEASURED,
            level=EvidenceLevel.E2,
            confidence=0.95,
            source_engine="manifest-inspector",
            engine_version="4.0.0",
            observation_type=ObservationType.DEPENDENCY_DECLARATION,
            artifact_type="dependency",
            description=f"Declared dependency: {dep_name}",
            symbol=dep_name,
            file_path=dep.get('file'),
            limitations=["Package declaration does not prove runtime cryptographic use."],
            provenance=Provenance(
                input_hash=hashlib.sha256(dep_name.encode()).hexdigest(),
                source_engine="manifest-inspector",
                engine_version="4.0.0",
                scan_id="",
                location=dep.get('file'),
            ),
            raw_details=dep
        )
        evidence_list.append(ev.to_dict())

    # Map source findings (Python AST -> E3 actual API call; Polyglot regex -> E1 pattern)
    for f in findings:
        is_ast = f.get('engine') == 'python-ast'
        ev_level = EvidenceLevel.E3 if is_ast else EvidenceLevel.E1
        obs_type = ObservationType.SOURCE_API_USE if is_ast else ObservationType.SOURCE_PATTERN
        ev = Evidence(
            state=EvidenceState.MEASURED,
            level=ev_level,
            confidence=0.95 if is_ast else 0.75,
            source_engine=f.get('engine', 'source-scan'),
            engine_version="4.0.0",
            rule_id=f.get('primitive'),
            rule_version="4.0.0",
            observation_type=obs_type,
            artifact_type="source",
            symbol=f.get('primitive'),
            file_path=f.get('file'),
            line_start=f.get('line'),
            line_end=f.get('line'),
            description=f.get('issue', f.get('description', 'Cryptographic API use observed')),
            limitations=["Static AST observation; dynamic dataflow not fully traced."] if is_ast else ["Regex heuristic observation."],
            raw_details={'code': f.get('code'), 'category': f.get('category'), 'severity': f.get('severity')},
            provenance=Provenance(
                input_hash=f.get('source_hash', ''),
                source_engine=f.get('engine', 'source-scan'),
                engine_version="4.0.0",
                scan_id="",
                location=f"{f.get('file')}:{f.get('line')}",
            )
        )
        evidence_list.append(ev.to_dict())

    return {'findings': findings, 'total_findings': len(findings),
            'critical_count': sum(f['severity'] == 'CRITICAL' for f in findings),
            'high_count': sum(f['severity'] == 'HIGH' for f in findings),
            'coverage': coverage, 'dependencies': dependencies,
            'evidence': evidence_list,
            'call_graph': call_graph,
            'observations': observations,
            'status': 'partial' if any(c['status'] in ('error', 'unsupported') for c in coverage) else 'success',
            'limitations': ['Non-Python rules are heuristic; no general interprocedural dataflow or dependency vulnerability database.'],
            'remediation': ''}


