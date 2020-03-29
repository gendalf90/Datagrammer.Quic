using Datagrammer.Quic.Protocol.Error;
using System;
using System.Text;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct ReasonPhrase
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private ReasonPhrase(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public override string ToString()
        {
            return Encoding.UTF8.GetString(bytes.Span);
        }

        public static ReasonPhrase Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            remainings = ReadOnlyMemory<byte>.Empty;

            var length = VariableLengthEncoding.Decode32(bytes.Span, out var decodedLength);
            var afterLengthBytes = bytes.Slice(decodedLength);

            if(afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            var reasonPhraseBytes = afterLengthBytes.Slice(0, length);

            remainings = afterLengthBytes.Slice(length);

            return new ReasonPhrase(reasonPhraseBytes);
        }
    }
}
