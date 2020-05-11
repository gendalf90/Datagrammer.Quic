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

        public static WritingContext StartWriting(Span<byte> destination)
        {
            var payloadContext = ExtensionPayload.StartWriting(destination);
            var vectorContext = ByteVector.StartVectorWriting(payloadContext.Remainings);

            return new WritingContext(destination, vectorContext.Remainings, vectorContext.Length + payloadContext.Length);
        }

        public static int FinishWriting(WritingContext context, Range range)
        {
            var payloadContext = ExtensionPayload.StartWriting(context.Start);
            var vectorContext = new WritingContext(payloadContext.Remainings, context.Remainings, payloadContext.Length - context.Remainings.Length);

            payloadContext.Move(ByteVector.FinishVectorWriting(vectorContext, range));

            return ExtensionPayload.FinishWriting(payloadContext);
        }
    }
}
