using System;

namespace Datagrammer.Quic.Protocol
{
    public static class MemoryCursorExtensions
    {
        public static void CopyTo(this Span<byte> bytes, MemoryCursor cursor)
        {
            var destination = cursor.Move(bytes.Length);

            bytes.CopyTo(destination);
        }

        public static void CopyTo(this Memory<byte> bytes, MemoryCursor cursor)
        {
            bytes.Span.CopyTo(cursor);
        }

        public static void CopyTo(this byte[] bytes, MemoryCursor cursor)
        {
            bytes.AsSpan().CopyTo(cursor);
        }
    }
}
