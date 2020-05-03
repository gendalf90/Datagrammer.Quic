using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class HandshakeLength
    {
        public static ReadOnlyMemory<byte> SliceHandshakeBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> afterHandshakeBytes)
        {
            if(bytes.Length < 3)
            {
                throw new EncodingException();
            }

            var lengthBytes = bytes.Slice(0, 3);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);
            var afterLengthBytes = bytes.Slice(3);

            if (afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            afterHandshakeBytes = afterLengthBytes.Slice(length);

            return afterLengthBytes.Slice(0, length);
        }
    }
}
