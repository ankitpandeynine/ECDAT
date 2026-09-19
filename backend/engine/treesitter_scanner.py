"""
ECDAT V4 Tree-Sitter Structural Cryptographic Scanner.

Structural parsing across 8 target languages:
Python, Java, C, C++, Go, Rust, JavaScript, TypeScript.

Core Research Principles:
1. IMPORT != ACTUAL_USE
2. DEPENDENCY != ACTUAL_USE
3. STRING_LITERAL / COMMENT != ACTUAL_USE
4. Structurally confirmed API sink invocation == ACTUAL_USE
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from tree_sitter import Language, Node, Parser
    import tree_sitter_c as tsc
    import tree_sitter_cpp as tscpp
    import tree_sitter_go as tsgo
    import tree_sitter_java as tsjava
    import tree_sitter_javascript as tsjs
    import tree_sitter_python as tspy
    import tree_sitter_rust as tsrust
    import tree_sitter_typescript as tsts
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

from .evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, Provenance
from .sink_database import get_sink_database


class ConstructType(str, Enum):
    IMPORT = "IMPORT"
    DECLARATION = "DECLARATION"
    CONSTANT = "CONSTANT"
    STRING_LITERAL = "STRING_LITERAL"
    COMMENT = "COMMENT"
    API_REFERENCE = "API_REFERENCE"
    API_CALL = "API_CALL"
    CRYPTO_SINK = "CRYPTO_SINK"
    ACTUAL_USE = "ACTUAL_USE"
    CANDIDATE = "CANDIDATE"


@dataclass
class SourceObservation:
    construct_type: ConstructType
    name: str
    line: int
    column: int
    code_snippet: str
    file_path: str = ""
    actual_use: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "construct_type": self.construct_type.value,
            "name": self.name,
            "line": self.line,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "file_path": self.file_path,
            "actual_use": self.actual_use,
            "details": self.details,
        }


class TreeSitterScanner:
    """Multi-language structural code parser with crypto sink and call-graph identification."""

    LANGUAGE_MAP = {
        "python": "python",
        "py": "python",
        "java": "java",
        "c": "c_cpp",
        "cpp": "c_cpp",
        "c_cpp": "c_cpp",
        "c++": "c_cpp",
        "h": "c_cpp",
        "hpp": "c_cpp",
        "golang": "golang",
        "go": "golang",
        "rust": "rust",
        "rs": "rust",
        "javascript": "javascript",
        "js": "javascript",
        "jsx": "javascript",
        "typescript": "typescript",
        "ts": "typescript",
        "tsx": "typescript",
    }

    def __init__(self):
        self.parsers: Dict[str, Parser] = {}
        self.languages: Dict[str, Language] = {}
        self.sink_db = get_sink_database()
        if TREE_SITTER_AVAILABLE:
            self._init_languages()

    def _init_languages(self) -> None:
        try:
            self.languages["python"] = Language(tspy.language())
            self.languages["java"] = Language(tsjava.language())
            self.languages["c_cpp"] = Language(tscpp.language())
            self.languages["golang"] = Language(tsgo.language())
            self.languages["rust"] = Language(tsrust.language())
            self.languages["javascript"] = Language(tsjs.language())
            self.languages["typescript"] = Language(tsts.language_typescript())
        except Exception:
            pass

    def is_available(self, language: str) -> bool:
        if not TREE_SITTER_AVAILABLE:
            return False
        normalized = self.LANGUAGE_MAP.get(language.lower(), language.lower())
        return normalized in self.languages

    def get_parser(self, language: str) -> Optional[Parser]:
        normalized = self.LANGUAGE_MAP.get(language.lower(), language.lower())
        if normalized not in self.languages:
            return None
        if normalized not in self.parsers:
            self.parsers[normalized] = Parser(self.languages[normalized])
        return self.parsers[normalized]


    def parse_and_scan(
        self,
        source_code: str,
        language: str,
        file_path: str = "",
        external_constants: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Parses source code structurally.
        If language parser is unavailable, returns explicit scanner-unavailable status.
        Never pretends parsing succeeded.
        """
        if not self.is_available(language):
            return {
                "status": "scanner_unavailable",
                "available": False,
                "inconclusive": True,
                "language": language,
                "error": f"Tree-sitter parser for {language} is unavailable in this environment.",
                "observations": [],
                "findings": [],
                "evidence": [],
                "call_graph": [],
                "constants": {},
            }

        parser = self.get_parser(language)
        if not parser:
            return {
                "status": "scanner_unavailable",
                "available": False,
                "inconclusive": True,
                "language": language,
                "observations": [],
                "findings": [],
                "evidence": [],
                "call_graph": [],
                "constants": {},
            }

        source_bytes = source_code.encode("utf-8")
        tree = parser.parse(source_bytes)
        source_lines = source_code.splitlines()

        constants = dict(external_constants or {})
        aliases: Dict[str, str] = {}
        observations: List[SourceObservation] = []
        findings: List[Dict[str, Any]] = []
        call_graph: List[Dict[str, Any]] = []
        evidence_list: List[Dict[str, Any]] = []

        # 1. First Pass: Collect Constants, Identifiers, and Import Aliases
        self._extract_constants_and_aliases(tree.root_node, source_bytes, constants, aliases)

        # 2. Second Pass: Structural Traversal
        self._traverse_node(
            node=tree.root_node,
            source_bytes=source_bytes,
            source_lines=source_lines,
            language=self.LANGUAGE_MAP.get(language.lower(), language.lower()),
            file_path=file_path,
            constants=constants,
            aliases=aliases,
            current_scope="<global>",
            observations=observations,
            findings=findings,
            call_graph=call_graph,
            evidence_list=evidence_list,
        )

        return {
            "status": "success",
            "available": True,
            "inconclusive": False,
            "language": language,
            "observations": [obs.to_dict() for obs in observations],
            "findings": findings,
            "evidence": evidence_list,
            "call_graph": call_graph,
            "constants": constants,
            "aliases": aliases,
            "total_findings": len(findings),
            "actual_use_count": sum(1 for obs in observations if obs.actual_use),
        }

    def _get_node_text(self, node: Node, source_bytes: bytes) -> str:
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _get_line_snippet(self, source_lines: List[str], lineno: int) -> str:
        if 1 <= lineno <= len(source_lines):
            return source_lines[lineno - 1].strip()
        return ""

    def _extract_constants_and_aliases(
        self, root: Node, source_bytes: bytes, constants: Dict[str, Any], aliases: Dict[str, str]
    ) -> None:
        """Deterministic constant and alias extraction from assignments and imports."""
        def visit(n: Node):
            # Assignments and variable declarations
            if n.type in ("assignment", "variable_declarator", "init_declarator", "short_var_decl"):
                text = self._get_node_text(n, source_bytes)
                m = re.search(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*(?:([0-9]+)|[\"']([^\"']+)[\"'])", text)
                if m:
                    var_name = m.group(1)
                    if m.group(2) is not None:
                        constants[var_name] = int(m.group(2))
                    elif m.group(3) is not None:
                        constants[var_name] = m.group(3)
                else:
                    m_alias = re.search(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*([a-zA-Z_][a-zA-Z0-9_\.]*)$", text.strip().rstrip(";"))
                    if m_alias:
                        aliases[m_alias.group(1)] = m_alias.group(2)

            # Import alias extraction
            elif n.type in ("import_statement", "import_from_statement", "use_declaration", "import_declaration"):
                text = self._get_node_text(n, source_bytes)
                m_imp = re.search(r"import\s+([a-zA-Z0-9_\.]+)\s+as\s+([a-zA-Z0-9_]+)", text)
                if m_imp:
                    aliases[m_imp.group(2)] = m_imp.group(1)
                m_from_as = re.search(r"from\s+([a-zA-Z0-9_\.]+)\s+import\s+([a-zA-Z0-9_]+)\s+as\s+([a-zA-Z0-9_]+)", text)
                if m_from_as:
                    aliases[m_from_as.group(3)] = f"{m_from_as.group(1)}.{m_from_as.group(2)}"
                m_from = re.search(r"from\s+([a-zA-Z0-9_\.]+)\s+import\s+([a-zA-Z0-9_]+)", text)
                if m_from and " as " not in text:
                    aliases[m_from.group(2)] = f"{m_from.group(1)}.{m_from.group(2)}"
                m_req = re.search(r"(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*require\([\"']([^\"']+)[\"']\)", text)
                if m_req:
                    aliases[m_req.group(1)] = m_req.group(2)
                m_rs = re.search(r"use\s+([a-zA-Z0-9_:]+)\s+as\s+([a-zA-Z0-9_]+)", text)
                if m_rs:
                    aliases[m_rs.group(2)] = m_rs.group(1)
                m_go = re.search(r"import\s+([a-zA-Z0-9_]+)\s+[\"']([^\"']+)[\"']", text)
                if m_go:
                    aliases[m_go.group(1)] = m_go.group(2)

            for child in n.children:
                visit(child)

        visit(root)

    def _resolve_with_aliases(self, func_name: str, aliases: Dict[str, str]) -> str:
        if not func_name:
            return ""
        if func_name in aliases:
            return aliases[func_name]
        if "." in func_name:
            parts = func_name.split(".", 1)
            if parts[0] in aliases:
                return f"{aliases[parts[0]]}.{parts[1]}"
        if "::" in func_name:
            parts = func_name.split("::", 1)
            if parts[0] in aliases:
                return f"{aliases[parts[0]]}::{parts[1]}"
        return func_name


    def _traverse_node(
        self,
        node: Node,
        source_bytes: bytes,
        source_lines: List[str],
        language: str,
        file_path: str,
        constants: Dict[str, Any],
        aliases: Dict[str, str],
        current_scope: str,
        observations: List[SourceObservation],
        findings: List[Dict[str, Any]],
        call_graph: List[Dict[str, Any]],
        evidence_list: List[Dict[str, Any]],
    ) -> None:

        lineno = node.start_point[0] + 1
        col = node.start_point[1]
        snippet = self._get_line_snippet(source_lines, lineno)

        # Track function/method definitions to form call graph
        if node.type in ("function_definition", "method_declaration", "function_item", "function_declaration"):
            # Extract function name
            name_node = node.child_by_field_name("name")
            if name_node:
                current_scope = self._get_node_text(name_node, source_bytes)

        # 1. COMMENT CONSTRUCT: NEVER ACTUAL USE
        if "comment" in node.type:
            comment_text = self._get_node_text(node, source_bytes)
            if re.search(r"\b(RSA|AES|DES|MD5|SHA-?1|SHA-?256|PQC|ML-KEM|Kyber)\b", comment_text, re.IGNORECASE):
                obs = SourceObservation(
                    construct_type=ConstructType.COMMENT,
                    name=comment_text[:50],
                    line=lineno,
                    column=col,
                    code_snippet=snippet,
                    file_path=file_path,
                    actual_use=False,
                    details={"comment": comment_text, "note": "Comments are non-executable candidate mentions."},
                )
                observations.append(obs)
            return

        # 2. IMPORT CONSTRUCT: NEVER ACTUAL USE
        if node.type in ("import_statement", "import_from_statement", "use_declaration", "import_declaration", "preproc_include"):
            import_text = self._get_node_text(node, source_bytes)
            obs = SourceObservation(
                construct_type=ConstructType.IMPORT,
                name=import_text,
                line=lineno,
                column=col,
                code_snippet=snippet,
                file_path=file_path,
                actual_use=False,
                details={"import_statement": import_text},
            )
            observations.append(obs)

            # Generate E2 import evidence
            ev = Evidence(
                state=EvidenceState.DECLARED,
                level=EvidenceLevel.E2,
                confidence=0.90,
                source_engine="tree-sitter",
                engine_version="4.0.0",
                observation_type=ObservationType.SOURCE_IMPORT,
                artifact_type="source",
                symbol=import_text.split()[-1],
                file_path=file_path,
                line_start=lineno,
                line_end=lineno,
                description=f"Source import: {import_text}",
                limitations=["Import declaration does not prove execution or actual cryptographic use."],
                provenance=Provenance(
                    input_hash=hashlib.sha256(import_text.encode()).hexdigest(),
                    source_engine="tree-sitter",
                    engine_version="4.0.0",
                    location=f"{file_path}:{lineno}",
                ),
            )
            evidence_list.append(ev.to_dict())
            return

        # 3. CALL CONSTRUCT: ACTUAL USE CANDIDATE
        if node.type in ("call", "call_expression", "method_invocation"):
            call_text = self._get_node_text(node, source_bytes)
            # Find callee / function target
            if node.type == "method_invocation":
                obj_node = node.child_by_field_name("object")
                name_node = node.child_by_field_name("name")
                if obj_node and name_node:
                    func_name = f"{self._get_node_text(obj_node, source_bytes)}.{self._get_node_text(name_node, source_bytes)}"
                elif name_node:
                    func_name = self._get_node_text(name_node, source_bytes)
                else:
                    func_name = ""
            else:
                func_node = (
                    node.child_by_field_name("function")
                    or node.child_by_field_name("name")
                    or (node.children[0] if node.children else None)
                )
                func_name = self._get_node_text(func_node, source_bytes) if func_node else ""

            # Resolve aliases
            resolved_func = self._resolve_with_aliases(func_name, aliases)
            resolved_call = self._resolve_with_aliases(call_text, aliases)

            # Check if this call matches any known cryptographic sink
            matched_sink = (
                self.sink_db.match_call(language, resolved_func)
                or self.sink_db.match_call(language, func_name)
                or self.sink_db.match_call(language, resolved_call)
                or self.sink_db.match_call(language, call_text)
            )
            if matched_sink:
                # Actual cryptographic API call identified!
                # Extract parameters / constant propagation
                resolved_key_size = self._resolve_key_size(call_text, constants)
                algorithm = matched_sink.get("algorithm", "Unknown")

                # If algorithm is generic (Cipher, KeyPairGenerator, MessageDigest, EVP_Cipher), extract from argument strings or constants
                arg_algo, const_prov = self._extract_algo_from_args(call_text, constants)
                if arg_algo:
                    algorithm = arg_algo

                if resolved_key_size and resolved_key_size != "UNKNOWN" and algorithm in ("RSA", "KeyPairGenerator"):
                    primitive_name = f"RSA-{resolved_key_size}"
                elif resolved_key_size and resolved_key_size != "UNKNOWN" and algorithm == "AES":
                    primitive_name = f"AES-{resolved_key_size}"
                else:
                    primitive_name = algorithm

                alias_prov = (
                    {"alias": func_name, "resolved": resolved_func}
                    if resolved_func and resolved_func != func_name
                    else None
                )

                obs = SourceObservation(
                    construct_type=ConstructType.ACTUAL_USE,
                    name=func_name or matched_sink.get("api", "CryptoAPI"),
                    line=lineno,
                    column=col,
                    code_snippet=snippet,
                    file_path=file_path,
                    actual_use=True,
                    details={
                        "sink": matched_sink,
                        "key_size": resolved_key_size,
                        "calling_scope": current_scope,
                        "constant_provenance": const_prov,
                        "alias_provenance": alias_prov,
                    },
                )
                observations.append(obs)

                # Add Call Graph edge
                call_graph.append({
                    "caller": current_scope,
                    "callee": primitive_name,
                    "file": file_path,
                    "line": lineno,
                    "relationship": "CALLS",
                })

                # Severity calculation
                risk = matched_sink.get("risk_relevance", "classical_secure")
                if risk in ("deprecated", "insecure_mode"):
                    severity = "CRITICAL"
                elif risk == "quantum_vulnerable":
                    severity = "HIGH" if (isinstance(resolved_key_size, int) and resolved_key_size <= 2048) else "MEDIUM"
                else:
                    severity = "LOW"

                finding = {
                    "file": file_path,
                    "line": lineno,
                    "code": snippet,
                    "primitive": primitive_name,
                    "algorithm": algorithm,
                    "category": matched_sink.get("category", "Cryptographic API"),
                    "severity": severity,
                    "issue": f"Cryptographic API use: {func_name} ({risk})",
                    "nist_recommendation": matched_sink.get("pqc_replacement") or "Follow NIST SP 800-131A / PQC standards.",
                    "quantum_risk": "Quantum vulnerable (Shor's algorithm)" if risk == "quantum_vulnerable" else "Classical/Standard cryptographic primitive.",
                    "actual_use": True,
                    "key_size": resolved_key_size,
                    "calling_scope": current_scope,
                    "language": language,
                    "engine": "tree-sitter",
                    "constant_provenance": const_prov,
                    "alias_provenance": alias_prov,
                }
                findings.append(finding)

                # Generate P0 E3 Evidence
                ev = Evidence(
                    state=EvidenceState.MEASURED,
                    level=EvidenceLevel.E3,
                    confidence=0.98,
                    source_engine="tree-sitter",
                    engine_version="4.0.0",
                    observation_type=ObservationType.SOURCE_API_USE,
                    artifact_type="source",
                    symbol=primitive_name,
                    file_path=file_path,
                    line_start=lineno,
                    line_end=lineno,
                    description=f"Actual cryptographic API use: {func_name}",
                    limitations=["Static structural observation; dynamic memory buffers not inspected."],
                    raw_details={
                        "call": call_text,
                        "resolved_call": resolved_call,
                        "key_size": resolved_key_size,
                        "caller": current_scope,
                        "sink": matched_sink,
                        "constant_provenance": const_prov,
                        "alias_provenance": alias_prov,
                    },
                    provenance=Provenance(
                        input_hash=hashlib.sha256(call_text.encode()).hexdigest(),
                        source_engine="tree-sitter",
                        engine_version="4.0.0",
                        location=f"{file_path}:{lineno}",
                    ),
                )
                evidence_list.append(ev.to_dict())

        # 4. STRING LITERAL CONSTRUCT: CANDIDATE ONLY, NEVER ACTUAL USE
        elif node.type in ("string", "string_literal", "interpreted_string_literal"):
            text = self._get_node_text(node, source_bytes).strip("\"'")
            if re.search(r"^(AES-(?:128|192|256)-GCM|RSA|MD5|SHA-256|DES)$", text, re.IGNORECASE):
                obs = SourceObservation(
                    construct_type=ConstructType.STRING_LITERAL,
                    name=text,
                    line=lineno,
                    column=col,
                    code_snippet=snippet,
                    file_path=file_path,
                    actual_use=False,
                    details={"string_value": text, "note": "String literal is a candidate, not proof of use."},
                )
                observations.append(obs)

        # Recurse children
        for child in node.children:
            self._traverse_node(
                node=child,
                source_bytes=source_bytes,
                source_lines=source_lines,
                language=language,
                file_path=file_path,
                constants=constants,
                aliases=aliases,
                current_scope=current_scope,
                observations=observations,
                findings=findings,
                call_graph=call_graph,
                evidence_list=evidence_list,
            )

    def _resolve_key_size(self, call_text: str, constants: Dict[str, Any]) -> Any:
        """Detects key_size argument from direct constant or propagated variable."""
        # 1. Direct integer match: key_size=2048 or initialize(2048) or GenerateKey(..., 1024)
        m = re.search(r"(?:key_size|bits|initialize|GenerateKey)\s*[=(,]\s*([0-9]+)", call_text)
        if m:
            return int(m.group(1))

        # 2. Constant variable propagation: key_size=KEY_SIZE or initialize(KEY_SIZE) or settings.BITS
        m_var = re.search(r"(?:key_size|bits|initialize|GenerateKey)\s*[=(,]\s*([a-zA-Z_][a-zA-Z0-9_\.]*)", call_text)
        if m_var:
            var_name = m_var.group(1)
            if var_name in constants:
                return constants[var_name]
            if "." in var_name and var_name.split(".")[-1] in constants:
                return constants[var_name.split(".")[-1]]


        # 3. Dynamic call or unknown expression: return UNKNOWN
        if any(token in call_text for token in ("key_size", "bits", "initialize", "GenerateKey")):
            return "UNKNOWN"

        return None

    def _extract_algo_from_args(
        self, call_text: str, constants: Optional[Dict[str, Any]] = None
    ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """Extracts algorithm / mode string passed as string literal argument or resolved constant."""
        # 1. Direct string literal match
        m = re.search(r"[\"']([A-Za-z0-9_\-\/]+)[\"']", call_text)
        if m:
            return self._normalize_algo_name(m.group(1)), None

        # 2. Indirect constant match: check arguments for variable names in constants
        if constants:
            m_args = re.search(r"\(([^)]+)\)", call_text)
            if m_args:
                arg_tokens = [t.strip().strip("\"'") for t in m_args.group(1).split(",")]
                for tok in arg_tokens:
                    clean_tok = tok.split("=")[-1].strip()
                    if clean_tok in constants and isinstance(constants[clean_tok], str):
                        val = constants[clean_tok]
                        norm = self._normalize_algo_name(val)
                        if norm:
                            return norm, {"variable": clean_tok, "resolved_value": val}

        return None, None

    def _normalize_algo_name(self, raw_name: str) -> Optional[str]:
        arg_val = raw_name.upper()
        if "AES" in arg_val:
            if "GCM" in arg_val:
                return "AES-GCM"
            if "CBC" in arg_val:
                return "AES-CBC"
            if "ECB" in arg_val:
                return "AES-ECB"
            return "AES"
        if "DES" in arg_val:
            if "TRIPLE" in arg_val or "DES3" in arg_val:
                return "TripleDES"
            if "ECB" in arg_val:
                return "DES-ECB"
            return "DES"
        if "RSA" in arg_val:
            return "RSA"
        if "MD5" in arg_val:
            return "MD5"
        if "SHA-256" in arg_val or "SHA256" in arg_val or "SHA_256" in arg_val:
            return "SHA-256"
        if "SHA-512" in arg_val or "SHA512" in arg_val or "SHA_512" in arg_val:
            return "SHA-512"
        if "SHA-1" in arg_val or "SHA1" in arg_val:
            return "SHA-1"
        if "ECDSA" in arg_val or "EC" in arg_val:
            return "ECDSA"
        return None



# Global singleton
_GLOBAL_TREESITTER_SCANNER: Optional[TreeSitterScanner] = None



def get_treesitter_scanner() -> TreeSitterScanner:
    global _GLOBAL_TREESITTER_SCANNER
    if _GLOBAL_TREESITTER_SCANNER is None:
        _GLOBAL_TREESITTER_SCANNER = TreeSitterScanner()
    return _GLOBAL_TREESITTER_SCANNER
