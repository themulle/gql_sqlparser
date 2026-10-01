namespace TrinoSqlEngine;

using System;
using System.IO;
using Antlr4.Runtime;
using Antlr4.Runtime.Atn;
using Antlr4.Runtime.Misc;
using Antlr4.Runtime.Tree;
using Microsoft.Extensions.ObjectPool;

public sealed class ThrowingErrorListener : BaseErrorListener, IAntlrErrorListener<int>
{
    public static readonly ThrowingErrorListener Instance = new();

    public override void SyntaxError(TextWriter output, IRecognizer recognizer, IToken offendingSymbol, int line, int charPositionInLine, string msg, RecognitionException e)
    {
        throw new ParseCanceledException($"line {line}:{charPositionInLine}: {msg}", e);
    }

    public void SyntaxError(TextWriter output, IRecognizer recognizer, int offendingSymbol, int line, int charPositionInLine, string msg, RecognitionException e)
    {
        throw new ParseCanceledException($"line {line}:{charPositionInLine}: {msg}", e);
    }
}

public sealed class FastSqlEngine
{
    private static readonly DefaultErrorStrategy FallbackErrorStrategy = new();

    private readonly ObjectPool<SqlBaseParser> _parserPool = 
        new DefaultObjectPool<SqlBaseParser>(new ParserPooledObjectPolicy());

    /// <summary>
    /// SEC-04: Maximum allowed SQL query length in characters to prevent algorithmic DoS and StackOverflow attacks.
    /// </summary>
    public int MaxQueryLength { get; set; } = 512_000;

    public (SqlBaseParser.SingleStatementContext Tree, CommonTokenStream Tokens) Parse(ReadOnlyMemory<char> sql)
    {
        if (sql.Length > MaxQueryLength)
        {
            throw new ArgumentOutOfRangeException(nameof(sql), $"SQL query length ({sql.Length}) exceeds the maximum allowed limit of {MaxQueryLength} characters.");
        }

        var charStream = new ZeroCopyCaseInsensitiveStream(sql);
        var lexer = new SqlBaseLexer(charStream);
        lexer.RemoveErrorListeners();
        lexer.AddErrorListener(ThrowingErrorListener.Instance);

        var tokens = new CommonTokenStream(lexer);
        
        var parser = _parserPool.Get();
        try
        {
            parser.TokenStream = tokens;

            // Stufe 1: Schneller SLL-Pfad (im Pool bereits vorkonfiguriert)
            try
            {
                var tree = parser.singleStatement();
                return (tree, tokens);
            }
            catch (ParseCanceledException)
            {
                // Stufe 2: Fallback auf LL(*)-Modus
                tokens.Reset();
                parser.Reset();
                parser.AddErrorListener(ThrowingErrorListener.Instance);
                parser.ErrorHandler = FallbackErrorStrategy;
                parser.Interpreter.PredictionMode = PredictionMode.LL;
                
                var tree = parser.singleStatement();
                if (parser.NumberOfSyntaxErrors > 0)
                {
                    throw new ParseCanceledException($"Parsing failed with {parser.NumberOfSyntaxErrors} syntax errors.");
                }
                return (tree, tokens);
            }
        }
        finally
        {
            _parserPool.Return(parser);
        }
    }

    public (SqlBaseParser.StandaloneExpressionContext Tree, CommonTokenStream Tokens) ParseExpression(ReadOnlyMemory<char> sql)
    {
        if (sql.Length > MaxQueryLength)
        {
            throw new ArgumentOutOfRangeException(nameof(sql), $"SQL expression length ({sql.Length}) exceeds the maximum allowed limit of {MaxQueryLength} characters.");
        }

        var charStream = new ZeroCopyCaseInsensitiveStream(sql);
        var lexer = new SqlBaseLexer(charStream);
        lexer.RemoveErrorListeners();
        lexer.AddErrorListener(ThrowingErrorListener.Instance);

        var tokens = new CommonTokenStream(lexer);
        
        var parser = _parserPool.Get();
        try
        {
            parser.TokenStream = tokens;

            // Stufe 1: Schneller SLL-Pfad (im Pool bereits vorkonfiguriert)
            try
            {
                var tree = parser.standaloneExpression();
                return (tree, tokens);
            }
            catch (ParseCanceledException)
            {
                // Stufe 2: Fallback auf LL(*)-Modus
                tokens.Reset();
                parser.Reset();
                parser.AddErrorListener(ThrowingErrorListener.Instance);
                parser.ErrorHandler = FallbackErrorStrategy;
                parser.Interpreter.PredictionMode = PredictionMode.LL;
                
                var tree = parser.standaloneExpression();
                if (parser.NumberOfSyntaxErrors > 0)
                {
                    throw new ParseCanceledException($"Parsing failed with {parser.NumberOfSyntaxErrors} syntax errors.");
                }
                return (tree, tokens);
            }
        }
        finally
        {
            _parserPool.Return(parser);
        }
    }

    /// <summary>
    /// Architecture A3: High-level Façade method for secure RLS rewriting.
    /// </summary>
    public string RewriteRls(ReadOnlyMemory<char> sql, RlsOptions? options = null)
    {
        var (tree, tokens) = Parse(sql);
        var listener = new RlsListener(tokens, options);
        ParseTreeWalker.Default.Walk(listener, tree);
        return listener.GetSecuredSql();
    }
}
