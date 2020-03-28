using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct MaxDataFrame
    {
        private MaxDataFrame(int maxDataLength)
        {
            MaxDataLength = maxDataLength;
        }

        public int MaxDataLength { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out MaxDataFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new MaxDataFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsMaxData())
            {
                return false;
            }

            var maxDataLength = VariableLengthEncoding.Decode32(afterTypeBytes.Span, out var decodedLength);
            
            result = new MaxDataFrame(maxDataLength);
            remainings = afterTypeBytes.Slice(decodedLength);

            return true;
        }
    }
}
