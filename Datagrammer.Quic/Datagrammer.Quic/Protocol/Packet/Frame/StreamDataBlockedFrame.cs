using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct StreamDataBlockedFrame
    {
        private StreamDataBlockedFrame(StreamId streamId, int dataLimit)
        {
            StreamId = streamId;
            DataLimit = dataLimit;
        }

        public StreamId StreamId { get; }

        public int DataLimit { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out StreamDataBlockedFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new StreamDataBlockedFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsStreamDataBlocked())
            {
                return false;
            }

            var streamId = StreamId.Parse(afterTypeBytes, out var afterStreamIdBytes);
            var dataLimit = VariableLengthEncoding.Decode32(afterStreamIdBytes.Span, out var decodedLength);

            result = new StreamDataBlockedFrame(streamId, dataLimit);
            remainings = afterStreamIdBytes.Slice(decodedLength);

            return true;
        }
    }
}
