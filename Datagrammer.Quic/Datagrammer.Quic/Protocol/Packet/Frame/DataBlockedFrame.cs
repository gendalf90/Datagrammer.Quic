using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct DataBlockedFrame
    {
        private DataBlockedFrame(int dataLimit)
        {
            DataLimit = dataLimit;
        }

        public int DataLimit { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out DataBlockedFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new DataBlockedFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsDataBlocked())
            {
                return false;
            }

            var dataLimit = VariableLengthEncoding.Decode32(afterTypeBytes.Span, out var decodedLength);

            result = new DataBlockedFrame(dataLimit);
            remainings = afterTypeBytes.Slice(decodedLength);

            return true;
        }
    }
}
