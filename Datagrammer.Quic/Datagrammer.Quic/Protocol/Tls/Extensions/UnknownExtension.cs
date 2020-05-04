using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct UnknownExtension
    {
        private UnknownExtension(ReadOnlyMemory<byte> rawData)
        {
            RawData = rawData;
        }

        public ReadOnlyMemory<byte> RawData { get; }

        public static UnknownExtension Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 4)
            {
                throw new EncodingException();
            }

            var payloadLengthBytes = bytes.Slice(2, 2);
            var payloadLength = (int)NetworkBitConverter.ParseUnaligned(payloadLengthBytes.Span);

            if(bytes.Length < payloadLength + 4)
            {
                throw new EncodingException();
            }

            var rawData = bytes.Slice(0, payloadLength + 4);

            remainings = bytes.Slice(payloadLength + 4);

            return new UnknownExtension(rawData);
        }
    }
}
