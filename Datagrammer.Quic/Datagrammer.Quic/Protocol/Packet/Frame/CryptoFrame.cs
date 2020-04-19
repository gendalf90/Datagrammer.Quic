using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct CryptoFrame
    {
        internal CryptoFrame(int offset, ReadOnlyMemory<byte> data)
        {
            Offset = offset;
            Data = data;
        }

        public int Offset { get; }

        public ReadOnlyMemory<byte> Data { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out CryptoFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new CryptoFrame();
            remainings = bytes;

            var type = FrameType.Parse(bytes, out var afterTypeRemainings);

            if (!type.IsCrypto())
            {
                return false;
            }

            var offset = VariableLengthEncoding.Decode32(afterTypeRemainings.Span, out var decodedLength);
            var afterOffsetBytes = afterTypeRemainings.Slice(decodedLength);
            var length = VariableLengthEncoding.Decode32(afterOffsetBytes.Span, out decodedLength);
            var afterLengthBytes = afterOffsetBytes.Slice(decodedLength);

            if(afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            var data = afterLengthBytes.Slice(0, length);
            var afterDataBytes = afterLengthBytes.Slice(length);

            result = new CryptoFrame(offset, data);
            remainings = afterDataBytes;

            return true;
        }
    }
}
