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

        public static WritingContext StartWriting(ref Span<byte> destination, Range range)
        {
            var payloadContext = ExtensionPayload.StartWriting(ref destination);
            var vectorContext = ByteVector.StartVectorWriting(ref destination, range);

            return new WritingContext(payloadContext, vectorContext);
        }

        public readonly ref struct WritingContext
        {
            private readonly ExtensionPayload.WritingContext payloadContext;
            private readonly ByteVector.WritingContext vectorContext;

            public WritingContext(ExtensionPayload.WritingContext payloadContext,
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
    }
}
