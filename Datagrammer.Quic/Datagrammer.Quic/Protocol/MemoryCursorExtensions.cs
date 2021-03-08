using System;

namespace Datagrammer.Quic.Protocol
{
    public static class MemoryCursorExtensions
    {
        public static void CopyTo(this Span<byte> bytes, MemoryCursor cursor)
        {
            var destination = cursor.Move(bytes.Length);

            bytes.CopyTo(destination.Span);
        }

        public static void CopyTo(this Memory<byte> bytes, MemoryCursor cursor)
        {
            bytes.Span.CopyTo(cursor);
        }

        public static void CopyTo(this byte[] bytes, MemoryCursor cursor)
        {
            bytes.AsSpan().CopyTo(cursor);
        }

        public static void CopyTo(this ReadOnlySpan<byte> bytes, MemoryCursor cursor)
        {
            var destination = cursor.Move(bytes.Length);

            bytes.CopyTo(destination.Span);
        }

        public static void CopyTo(this ReadOnlyMemory<byte> bytes, MemoryCursor cursor)
        {
            bytes.Span.CopyTo(cursor);
        }

        public static Memory<byte> Read(this MemoryBuffer buffer, MemoryCursor cursor)
        {
            using (buffer.SetCursor(cursor))
            {
                return cursor.PeekEnd();
            }
        }

        public static void CopyTo(this ValueBuffer buffer, MemoryCursor cursor)
        {
            var bytes = cursor.Move(buffer.Length);

            buffer.CopyTo(bytes.Span);
        }

        public static MemoryBuffer Slice(this MemoryCursor cursor, int length)
        {
            var startOffset = cursor.AsOffset();

            cursor.Move(length);

            return new MemoryBuffer(Math.Min(startOffset, cursor), Math.Abs(length));
        }

        public static MemoryBuffer SliceEnd(this MemoryCursor cursor)
        {
            var startOffset = cursor.AsOffset();

            cursor.MoveEnd();

            return new MemoryBuffer(startOffset, cursor - startOffset);
        }
    }
}
