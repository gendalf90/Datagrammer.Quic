using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class ExtensionVectorPayload
    {
        public static ReadOnlyMemory<byte> Slice(ReadOnlyMemory<byte> bytes, Range range, out ReadOnlyMemory<byte> afterPayloadBytes)
        {
            var payload = ExtensionPayload.Slice(bytes, out afterPayloadBytes);
            var vectorBytes = ByteVector.SliceVectorBytes(payload, range, out var afterVectorBytes);

            if(!afterVectorBytes.IsEmpty)
            {
                throw new EncodingException();
            }

            return vectorBytes;
        }

        public static WritingContext StartWriting(Span<byte> destination, Range range)
        {
            var payloadContext = ExtensionPayload.StartWriting(destination);
            var vectorContext = ByteVector.StartVectorWriting(payloadContext.Cursor.Destination, range);

            return new WritingContext(payloadContext, vectorContext);
        }

        public ref struct WritingContext
        {
            private ExtensionPayload.WritingContext payloadContext;
            private ByteVector.WritingContext vectorContext;

            public WritingContext(ExtensionPayload.WritingContext payloadContext,
                                  ByteVector.WritingContext vectorContext)
            {
                this.payloadContext = payloadContext;
                this.vectorContext = vectorContext;

                Cursor = vectorContext.Cursor;
            }

            public WritingCursor Cursor { get; set; }

            public int Complete()
            {
                payloadContext.Cursor = payloadContext.Cursor.Move(vectorContext.Complete());

                return payloadContext.Complete();
            }
        }
    }
}
