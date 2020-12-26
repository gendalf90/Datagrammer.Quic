using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class ExtensionVectorLength
    {
        public static MemoryBuffer Slice(MemoryCursor cursor, Range range)
        {
            var payload = ExtensionLength.Slice(cursor);

            using (payload.SetCursor(cursor))
            {
                return ByteVector.SliceVectorBytes(cursor, range);
            }
        }

        public static ReadOnlyMemory<byte> Slice(ReadOnlyMemory<byte> bytes, Range range, out ReadOnlyMemory<byte> afterPayloadBytes)
        {
            var payload = ExtensionLength.Slice(bytes, out afterPayloadBytes);
            var vectorBytes = ByteVector.SliceVectorBytes(payload, range, out var afterVectorBytes);

            if(!afterVectorBytes.IsEmpty)
            {
                throw new EncodingException();
            }

            return vectorBytes;
        }

        public static WritingContext StartWriting(ref Span<byte> destination, Range range)
        {
            var payloadContext = ExtensionLength.StartWriting(ref destination);
            var vectorContext = ByteVector.StartVectorWriting(ref destination, range);

            return new WritingContext(payloadContext, vectorContext);
        }

        public static CursorWritingContext StartWriting(MemoryCursor cursor, Range range)
        {
            var payloadContext = ExtensionLength.StartWriting(cursor);
            var vectorContext = ByteVector.StartVectorWriting(cursor, range);

            return new CursorWritingContext(payloadContext, vectorContext);
        }

        public readonly ref struct WritingContext
        {
            private readonly ExtensionLength.WritingContext payloadContext;
            private readonly ByteVector.WritingContext vectorContext;

            public WritingContext(ExtensionLength.WritingContext payloadContext,
                                  ByteVector.WritingContext vectorContext)
            {
                this.payloadContext = payloadContext;
                this.vectorContext = vectorContext;
            }

            public void Complete(ref Span<byte> bytes)
            {
                vectorContext.Complete(ref bytes);
                payloadContext.Complete(ref bytes);
            }
        }

        public readonly ref struct CursorWritingContext
        {
            private readonly ExtensionLength.CursorWritingContext payloadContext;
            private readonly ByteVector.CursorWritingContext vectorContext;

            public CursorWritingContext(ExtensionLength.CursorWritingContext payloadContext,
                                        ByteVector.CursorWritingContext vectorContext)
            {
                this.payloadContext = payloadContext;
                this.vectorContext = vectorContext;
            }

            public void Dispose()
            {
                vectorContext.Dispose();
                payloadContext.Dispose();
            }
        }
    }
}
