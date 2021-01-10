using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public static class VariableLengthPayload
    {
        public static MemoryBuffer SliceBytes(MemoryCursor cursor)
        {
            var length = cursor.DecodeVariable32();

            return cursor.Slice(length);
        }

        public static CursorWritingContext StartWriting(MemoryCursor cursor)
        {
            return new CursorWritingContext(cursor, cursor.AsOffset());
        }

        public readonly ref struct CursorWritingContext
        {
            private readonly MemoryCursor cursor;
            private readonly int startOffset;

            public CursorWritingContext(
                MemoryCursor cursor,
                int startOffset)
            {
                this.cursor = cursor;
                this.startOffset = startOffset;
            }

            public void Dispose()
            {
                var length = cursor - startOffset;
                var payload = cursor.Move(-length);

                Span<byte> payloadBuffer = stackalloc byte[length];

                payload.Span.CopyTo(payloadBuffer);
                cursor.EncodeVariable32(length);
                payloadBuffer.CopyTo(cursor);
            }
        }
    }
}
