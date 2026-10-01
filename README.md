# FastSqlEngine (Trino-compatible SQL Parser for C# / .NET)

High-performance SQL Parser and Row-Level Security (RLS) query rewriter in C# / .NET 10, based on the Trino ANTLR4 grammar.

## Features

- **Ported Trino ANTLR4 Grammar ([`SqlBase.g4`](file:///root/gql_sqlparser/SqlBase.g4)):** Cleaned of Java artifacts, with C# keyword safety and native namespace integration.
- **Zero-Allocation Case-Insensitive Stream ([`ZeroCopyCaseInsensitiveStream.cs`](file:///root/gql_sqlparser/ZeroCopyCaseInsensitiveStream.cs)):** Uppercasing on-the-fly directly in CPU registers without heap allocations.
- **Global ATN/DFA Caching ([`SharedParserCache.cs`](file:///root/gql_sqlparser/SharedParserCache.cs)):** Static process-wide reuse of ANTLR decision tables.
- **Object Pooling ([`ParserPooledObjectPolicy.cs`](file:///root/gql_sqlparser/ParserPooledObjectPolicy.cs)):** High-throughput pooling of parser instances via `Microsoft.Extensions.ObjectPool`.
- **Two-Stage Execution Engine ([`FastSqlEngine.cs`](file:///root/gql_sqlparser/FastSqlEngine.cs)):** Fast $O(n)$ `SLL` parsing with seamless fallback to full `LL(*)` upon ambiguity.
- **RLS Rewriter ([`RlsListener.cs`](file:///root/gql_sqlparser/RlsListener.cs)):** Precise AST rewriting with `TokenStreamRewriter`, preserving original formatting and isolating CTEs.
- **Automated Trino Compliance Test Suite ([`TrinoParserComplianceTests.cs`](file:///root/gql_sqlparser/TrinoParserComplianceTests.cs)):** 760+ test cases extracted automatically from Trino's `TestSqlParser.java`.

---

## Legal & Licensing Compliance

This project complies with the licensing requirements of the underlying open-source components:

- **Original Grammar & Code:** Derived from the [Trino project](https://github.com/trinodb/trino), licensed under the **Apache License, Version 2.0**.
- **Modification Notice:** In compliance with Section 4(b) of the Apache License 2.0, all modified files (including [`SqlBase.g4`](file:///root/gql_sqlparser/SqlBase.g4)) contain explicit attribution and modification notices.
- **ANTLR 4 Runtime:** Licensed under the **BSD 3-Clause License**.
- **License & Notice Files:**
  - Full license texts are provided in [`LICENSE`](file:///root/gql_sqlparser/LICENSE) and [`THIRD_PARTY_NOTICES.md`](file:///root/gql_sqlparser/THIRD_PARTY_NOTICES.md).
  - Attribution notices are recorded in [`NOTICE`](file:///root/gql_sqlparser/NOTICE).
  - Test fixture provenance is documented in [`Fixtures/README.md`](file:///root/gql_sqlparser/Fixtures/README.md).
- **Trademark Disclaimer:** *Trino* is a trademark of its respective owners. This project is an independent C# implementation compatible with the Trino SQL dialect and is not endorsed by or affiliated with the Trino Software Foundation.

---

## Build and Run

```bash
# Build and run the pipeline demo & fixture extraction
dotnet run

# Run full test suite (760+ compliance tests)
dotnet test
```
