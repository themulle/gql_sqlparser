# TrinoSqlEngine: High-Performance SQL Parser & RLS Rewriter for .NET 10

[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4.svg)](https://dotnet.microsoft.com/)
[![C# 14](https://img.shields.io/badge/C%23-14-239120.svg)](https://learn.microsoft.com/dotnet/csharp/)
[![ANTLR 4](https://img.shields.io/badge/ANTLR-4.13.1-C9252B.svg)](https://www.antlr.org/)
[![Tests](https://img.shields.io/badge/Compliance%20Tests-779%20Passing-brightgreen.svg)]()
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A high-throughput, allocation-optimized SQL parser and Row-Level Security (RLS) query rewriting engine in C# / .NET 10, ported from the official [Trino](https://github.com/trinodb/trino) ANTLR4 grammar (`SqlBase.g4`).

Designed for high-scale multi-tenant data gateways, database proxies, and analytical query engines requiring zero-overhead security enforcement and standard SQL compliance.

---

## Key Highlights & Performance Architecture

### 1. Zero-Allocation Case-Insensitive Character Stream
* **Branchless CPU Uppercasing:** Processes ASCII characters on-the-fly (`(uint)(c - 'a') <= ('z' - 'a') ? (char)(c - 32) : char.ToUpperInvariant(c)`) directly in CPU registers without allocating temporary uppercase strings.
* **`LA(1)` Inlined Fast Path:** Inlined lookahead shortcut for `i == 1` (>95% of lexer accesses) with zero bounds-check overhead.
* **Direct Substring Slicing:** Avoids memory buffer copies by maintaining string slice offsets for sub-nanosecond token retrieval.

### 2. Global ATN & DFA Decision Table Caching
* Static process-wide reuse of ANTLR `ATN` and `DFA` decision tables (`SharedParserCache.cs`).
* Eliminates expensive DFA state re-initialization across threads and requests.

### 3. Parser Object Pooling & Zero-Allocation SLL Path
* High-throughput pooling using `Microsoft.Extensions.ObjectPool`.
* **Two-Stage Execution Engine:**
  1. **Stage 1 (SLL Fast-Path):** Executes linear $O(n)$ prediction with a pre-configured, reusable `BailErrorStrategy`. 0 bytes allocated for error listeners or strategy objects during normal execution.
  2. **Stage 2 (LL(*) Fallback):** Automatically recovers and resolves ambiguities using full contextual lookahead if `ParseCanceledException` occurs.

### 4. $O(1)$ Precomputed Keyword Table
* Replaces runtime regular expressions on non-reserved keyword predicates (`isKeyword`) with a fixed 512-byte L1-cache-friendly `bool[]` lookup table.

### 5. .NET 10 Runtime Tuning
* Enabled Dynamic PGO (`<TieredPGO>true</TieredPGO>`).
* Dynamic Adaptation To Application Sizes GC (`<GarbageCollectionAdaptationMode>1</GarbageCollectionAdaptationMode>`).
* Aggressive inlining (`[MethodImpl(MethodImplOptions.AggressiveInlining)]`) across critical loop paths.

---

## Row-Level Security (RLS) Query Rewriter

The engine includes a production-grade AST query rewriter (`RlsListener.cs`) backed by ANTLR's `TokenStreamRewriter`. It guarantees precise SQL transformation without destroying user formatting, indentation, or comments.

### Supported Operations & Strategies

| Statement | Rewrite Strategy | Security Enforcement |
| :--- | :--- | :--- |
| **`SELECT`** | Rewrites table references to `(SELECT * FROM table WHERE {filter}) [AS table]` | Lexical CTE scope isolation, PTF table argument rewriting |
| **`DELETE`** | Injects/merges filter into `WHERE`: `WHERE ({filter}) AND ({existingWhere})` | Strict parenthesization (prevents boolean `OR 1=1` bypass) |
| **`UPDATE`** | Injects/merges filter into `WHERE`: `WHERE ({filter}) AND ({existingWhere})` | `WITH CHECK OPTION`: blocks modification of tenant ID column |
| **`INSERT`** | Rewrites underlying query sources | `WITH CHECK OPTION`: validates inline `VALUES` and constant `SELECT` projections |

### Built-in Security Protections

* **CTE Shadowing Defense (ANSI SQL Lexical Scoping):**
  CTE names are added to scope on *exit* of the CTE definition, not entry. This prevents attacks where an attacker defines `WITH orders AS (SELECT * FROM orders) SELECT * FROM orders` in an attempt to bypass physical table filtering in the inner query.
* **Quoted & Normalized Identifiers:**
  Resilient against quote bypasses (`"orders"`, `` `orders` ``, `[orders]`). The engine strips quoting for policy verification while preserving the exact original representation in the rewritten output.
* **Polymorphic Table Functions (PTF):**
  Secures `TABLE(...)` arguments passed to table functions (e.g., `SELECT * FROM TABLE(my_ptf(TABLE(orders)))`).
* **Operator Precedence Protection:**
  Every injected predicate is wrapped in parentheses (`({policyFilter}) AND ({userPredicate})`), preventing operator precedence hijack attacks.
* **Administrative DDL Lockout:**
  Strict whitelisting automatically rejects administrative and data definition statements (`DROP`, `TRUNCATE`, `ALTER`, `CREATE`, `MERGE`, `GRANT`).

---

## Usage Examples

### 1. Basic RLS Query Rewriting

```csharp
using System;
using TrinoSqlEngine;

var engine = new FastSqlEngine();

// Default policy appends tenant_id = 42
string sql = "SELECT id, total FROM orders WHERE total > 100";
string secured = engine.RewriteRls(sql.AsMemory());

Console.WriteLine(secured);
// Output:
// SELECT id, total FROM (SELECT * FROM orders WHERE tenant_id = 42) WHERE total > 100
```

### 2. Custom Multi-Tenant Policy Provider

```csharp
using TrinoSqlEngine;

var options = new RlsOptions
{
    // Configure custom tenant filter and table matching
    PolicyProvider = new DefaultRlsPolicyProvider(
        defaultFilter: "organization_id = 'org_abc123'",
        predicate: tableName => tableName.Equals("orders", StringComparison.OrdinalIgnoreCase)
    ),
    // Append table alias if query relies on table-qualified columns
    AppendTableAlias = true
};

string sql = "SELECT orders.id, customers.name FROM orders JOIN customers ON orders.cust_id = customers.id";
string secured = engine.RewriteRls(sql.AsMemory(), options);

Console.WriteLine(secured);
// Output:
// SELECT orders.id, customers.name FROM (SELECT * FROM orders WHERE organization_id = 'org_abc123') AS orders JOIN customers ON orders.cust_id = customers.id
```

### 3. DML Rewriting with WITH CHECK OPTION

```csharp
using TrinoSqlEngine;

var options = new RlsOptions
{
    EnforceReadOnlyQueries = false,          // Allow DML rewriting
    EnforceWithCheckOption = true,          // Validate INSERT & UPDATE
    TenantColumnName = "tenant_id",
    ExpectedTenantValue = "42",
    DisallowTenantColumnModificationInUpdate = true
};

// 1. DELETE rewrite
string deleteSql = "DELETE FROM orders WHERE id = 10 OR 1=1";
string securedDelete = engine.RewriteRls(deleteSql.AsMemory(), options);
// Output: DELETE FROM orders WHERE (tenant_id = 42) AND (id = 10 OR 1=1)

// 2. UPDATE rewrite
string updateSql = "UPDATE orders SET status = 'shipped' WHERE id = 10";
string securedUpdate = engine.RewriteRls(updateSql.AsMemory(), options);
// Output: UPDATE orders SET status = 'shipped' WHERE (tenant_id = 42) AND (id = 10)

// 3. WITH CHECK OPTION rejection (throws SecurityException)
string maliciousInsert = "INSERT INTO orders (id, tenant_id) VALUES (1, 99)";
engine.RewriteRls(maliciousInsert.AsMemory(), options); 
// Throws: System.Security.SecurityException ("Tenant column 'tenant_id' inserted value '99' does not match expected tenant '42'.")
```

---

## Compliance Test Suite

The engine includes automated compliance testing derived directly from the official Trino repository (`io.trino.sql.parser.TestSqlParser`):

* **761 Compliance Tests:** Full coverage of complex SQL constructs (`SELECT`, `JOIN`, `WITH [RECURSIVE]`, window functions, pattern matching, `GROUPING SETS`, JSON operators, DML).
* **18 Security & Edge-Case Tests:** Verification of CTE shadowing, quoted identifiers, operator precedence, PTF arguments, and `WITH CHECK OPTION`.

### Running Tests

```bash
# Run all 779 tests
dotnet test

# Run demo application & extract latest Trino test fixtures
dotnet run
```

---

## Project Structure

```text
├── FastSqlEngine.cs               # Two-stage parsing engine & facade API
├── RlsListener.cs                 # AST listener for RLS & DML rewriting
├── IRlsPolicyProvider.cs          # Policy provider interfaces & RlsOptions
├── ZeroCopyCaseInsensitiveStream.cs # Register-based case-insensitive ICharStream
├── SharedParserCache.cs           # Global ATN/DFA static cache
├── ParserPooledObjectPolicy.cs    # Object pool policy for SqlBaseParser
├── SqlKeywords.cs                 # Precomputed O(1) keyword lookup table
├── SqlBase.g4                     # Modified Trino ANTLR4 grammar
├── TrinoTestExtractor.cs          # Automated test extraction utility
├── TrinoParserComplianceTests.cs  # xUnit compliance test suite (779 tests)
├── LICENSE                        # Apache License 2.0
├── NOTICE                         # Attribution notices
├── THIRD_PARTY_NOTICES.md         # Third-party license documentation
└── Fixtures/                      # Extracted Trino test fixtures
```

---

## Legal & License Notice

* **Grammar & Dialect:** Derived from the [Trino project](https://github.com/trinodb/trino), licensed under the **Apache License, Version 2.0**.
* **Modifications:** In compliance with Section 4(b) of the Apache License 2.0, all modified files (including [`SqlBase.g4`](SqlBase.g4)) contain explicit modification headers.
* **ANTLR 4 Runtime:** Licensed under the **BSD 3-Clause License**.
* **Disclaimers:** Full license texts are documented in [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Attributions are listed in [`NOTICE`](NOTICE). *Trino* is a trademark of its respective owners; this project is an independent C# implementation and is not affiliated with or endorsed by Trino.
