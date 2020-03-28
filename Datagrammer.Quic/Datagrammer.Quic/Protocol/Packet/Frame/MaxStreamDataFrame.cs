using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct MaxStreamDataFrame
    {
        private MaxStreamDataFrame(StreamId streamId, int maxDataLength)
        {
            StreamId = streamId;
            MaxDataLength = maxDataLength;
        }

        public StreamId StreamId { get; }

        public int MaxDataLength { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out MaxStreamDataFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new MaxStreamDataFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsMaxStreamData())
            {
                return false;
            }

            var streamId = StreamId.Parse(afterTypeBytes, out var afterStreamIdBytes);
            var maxDataLength = VariableLengthEncoding.Decode32(afterStreamIdBytes.Span, out var decodedLength);

            result = new MaxStreamDataFrame(streamId, maxDataLength);
            remainings = afterStreamIdBytes.Slice(decodedLength);

            return true;
        }
    }
}
