"""The call graph's data model: what a method, a call site and the index
holding them look like.

No parsing and no traversal, so every other module in the package imports
this one without pulling tree-sitter in with it.
"""
from dataclasses import dataclass, field


# An arity we could not read off a mapper interface, matched by callers_of()
# against any argument count. A mapper XML names its method but never its
# parameter list, so when the namespace lookup comes up empty a caller with
# the wrong arity is still a better answer than no caller at all -- the same
# trade this module's docstring makes for name matching generally.
ANY_ARITY = -1

# Hops from a sink back to a request handler. 3 was chosen when the walk was
# depth-first and every extra hop multiplied the work; with the breadth-first
# walk in trace_to_entry_points() the cost is flat enough to set this from
# the code instead. Measured on the vmscode corpus (64 candidates), candidates
# with no reachable entry point: depth 3 -> 22, depth 5 -> 14, depth 7 -> 13,
# depth 10 and 15 -> 13. So 7 is where a real layered Spring app saturates,
# not a round number: the last chain it recovers is TemplateUtil.writeFile <-
# ExportUtil x3 <- VulnerabilityService x3 <- an @PostMapping handler, checked
# hop by hop against the source. The whole sweep costs 1.8s.
MAX_DEPTH = 7


@dataclass
class Owner:
    """The class, interface or anonymous class body a method is declared in.

    Tracked because "nothing calls this method" is not one situation but
    several, and the supertype is what tells them apart. An @Override nobody
    calls inside `new X509TrustManager() {...}` is a TLS callback the JDK
    invokes; the same shape inside a class implementing the application's own
    OaUpdateServiceInterface is a strategy the application dispatches, and can
    carry a message payload. Handing the verify stage the type instead of a
    shrug is the difference between a confident verdict and a coin flip.
    """
    name: str = ""
    supertypes: tuple[str, ...] = ()
    anonymous: bool = False


@dataclass
class Method:
    file: str
    name: str
    arity: int
    start_line: int
    end_line: int
    return_type: str = ""
    owner: Owner = field(default_factory=Owner)
    overrides_supertype: bool = False
    entry_reason: str = ""
    # Whether entry_reason is proof or only a hint. A mapping annotation, or
    # a parameter the framework binds from the request, only ever appears on
    # a real handler. A parameter *type* does not: any helper can be handed
    # an HttpServletRequest or a MultipartFile, and treating those as proof
    # made trace_to_entry_points stop at the helper and never show the
    # handlers that call it -- which is where the validation lives.
    entry_definitive: bool = False

    @property
    def is_entry_point(self) -> bool:
        return bool(self.entry_reason)


@dataclass
class Call:
    file: str
    callee: str
    arity: int
    line: int
    caller: Method | None
    # `this.x()` / `super.x()`, which cannot land in an unrelated class. The
    # rest of the graph matches on name and arity alone, and `run()` is the
    # case that proves the cost: MockUserLoginInit.refreshMockUser() calls
    # `this.run()`, and without this flag that edge bridged into a completely
    # different module's OracleAQConsumer.run(), inventing a chain from a
    # @KafkaListener to a JMS connector it has nothing to do with.
    receiver_is_self: bool = False


@dataclass
class Index:
    methods: list[Method] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    # Type name -> its direct supertypes, and the transitive closure of that,
    # built once by index_workspace. Real hierarchies are more than one level
    # deep -- FileInfoDataUpload extends AbstractDeviceDataUpload extends
    # AbstractDataUpload -- and a one-level check silently drops the middle.
    supertypes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    ancestors: dict[str, frozenset[str]] = field(default_factory=dict)
    # Identifier-shaped string literal -> the files it appears in. Lets
    # "nothing calls this method" be followed by "but its name is a string
    # in OaEnum.java", which is the difference between a shrug and a lead.
    string_literals: dict[str, set[str]] = field(default_factory=dict)

    def methods_named(self, name: str, arity: int) -> list[Method]:
        return [m for m in self.methods if m.name == name and m.arity == arity]
