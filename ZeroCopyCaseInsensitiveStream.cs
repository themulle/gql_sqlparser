namespace TrinoSqlEngine;

using System;
using System.Runtime.InteropServices;
using Antlr4.Runtime;
using Antlr4.Runtime.Misc;

public sealed class ZeroCopyCaseInsensitiveStream : ICharStream
{
    private readonly ReadOnlyMemory<char> _memory;
    private readonly string? _strSource;
    private int _index;

    public ZeroCopyCaseInsensitiveStream(ReadOnlyMemory<char> source)
    {
        _memory = source;
        if (MemoryMarshal.TryGetString(source, out string? text, out int start, out int length) 
            && start == 0 && length == text.Length)
        {
            _strSource = text;
        }
        _index = 0;
    }

    public int Index => _index;
    public int Size => _memory.Length;
    public string SourceName => IntStreamConstants.UnknownSourceName;

    public void Consume()
    {
        if (_index < _memory.Length) _index++;
    }

    public int LA(int i)
    {
        if (i == 0) return 0;
        
        // SEC-07: Overflow-safe index calculation
        long targetLong = i > 0 ? (long)_index + i - 1 : (long)_index + i;
        if (targetLong < 0 || targetLong >= _memory.Length) return IntStreamConstants.EOF;

        int target = (int)targetLong;
        
        // P2: Fast direct indexing if backed by string
        char c = _strSource != null ? _strSource[target] : _memory.Span[target];

        // P1: Branchless ASCII uppercase ('a'..'z' -> 'A'..'Z')
        return (uint)(c - 'a') <= ('z' - 'a') ? (char)(c - 32) : char.ToUpperInvariant(c);
    }

    public int Mark() => -1;
    public void Release(int marker) { }
    public void Seek(int index) => _index = Math.Clamp(index, 0, _memory.Length);

    public string GetText(Interval interval)
    {
        int start = interval.a;
        int stop = interval.b;
        if (start < 0 || stop < start || stop >= _memory.Length) return string.Empty;
        return _memory.Slice(start, stop - start + 1).ToString();
    }
}
