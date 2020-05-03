using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct Extension
    {
        internal Extension(ushort type, ReadOnlyMemory<byte> data)
        {
            Type = type;
            Data = data;
        }

        public ushort Type { get; }

        public ReadOnlyMemory<byte> Data { get; }

        public static Extension Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 4)
            {
                throw new EncodingException();
            }

            var typeBytes = bytes.Slice(0, 2);
            var type = (ushort)NetworkBitConverter.ParseUnaligned(typeBytes.Span);
            var payloadLengthBytes = bytes.Slice(2, 2);
            var payloadLength = (int)NetworkBitConverter.ParseUnaligned(payloadLengthBytes.Span);
            
            if(bytes.Length < payloadLength + 4)
            {
                throw new EncodingException();
            }

            var payload = bytes.Slice(4, payloadLength);

            remainings = bytes.Slice(payloadLength + 4);

            return new Extension(type, payload);
        }
    }
}
