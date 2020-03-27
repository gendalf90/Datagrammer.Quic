using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct CryptoFrame
    {
        public CryptoFrame(int offset,
                           ReadOnlyMemory<byte> data)
        {
            Offset = offset;
            Data = data;
        }

        public int Offset { get; }

        public ReadOnlyMemory<byte> Data { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out CryptoFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new CryptoFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            if (!FrameType.TryParseFrameType(bytes, out var type, out var afterTypeRemainings))
            {
                return false;
            }

            if (!type.IsCrypto())
            {
                return false;
            }

            if (!VariableLengthEncoding.TryDecode32(afterTypeRemainings.Span, out var offset, out var decodedLength))
            {
                return false;
            }

            var afterOffsetBytes = afterTypeRemainings.Slice(decodedLength);

            if (!VariableLengthEncoding.TryDecode32(afterOffsetBytes.Span, out var length, out decodedLength))
            {
                return false;
            }

            var afterLengthBytes = afterOffsetBytes.Slice(decodedLength);

            if(afterLengthBytes.Length < length)
            {
                return false;
            }

            var data = afterLengthBytes.Slice(0, length);
            var afterDataBytes = afterLengthBytes.Slice(length);

            result = new CryptoFrame(offset, data);
            remainings = afterDataBytes;

            return true;
        }
    }
}
