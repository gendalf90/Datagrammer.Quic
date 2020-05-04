using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class ExtensionLength
    {
        public static ReadOnlyMemory<byte> SlicePayload(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> afterPayloadBytes)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var payloadLengthBytes = bytes.Slice(0, 2);
            var payloadLength = (int)NetworkBitConverter.ParseUnaligned(payloadLengthBytes.Span);

            if(bytes.Length < payloadLength + 2)
            {
                throw new EncodingException();
            }

            afterPayloadBytes = bytes.Slice(payloadLength + 2);

            return bytes.Slice(2, payloadLength);
        }

        public static WritingContext StartPayloadWriting(Span<byte> destination)
        {
            return WritingContext.Initialize(destination, 2);
        }

        public static int FinishPayloadWriting(WritingContext context)
        {
            if(context.Length < 2)
            {
                throw new EncodingException();
            }

            var length = context.Length - 2;

            if (length > ushort.MaxValue)
            {
                throw new EncodingException();
            }

            NetworkBitConverter.WriteUnaligned(context.Initial, (ulong)length, 2);

            return context.Length;
        }
    }
}
