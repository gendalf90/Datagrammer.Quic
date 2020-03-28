using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct MaxStreamsFrame
    {
        private MaxStreamsFrame(int maxStreams,
                                bool forBidirectional,
                                bool forUnidirectional)
        {
            MaxStreams = maxStreams;
            ForBidirectional = forBidirectional;
            ForUnidirectional = forUnidirectional;
        }

        public int MaxStreams { get; }

        public bool ForBidirectional { get; }

        public bool ForUnidirectional { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out MaxStreamsFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new MaxStreamsFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsMaxStreams())
            {
                return false;
            }

            var maxStreams = VariableLengthEncoding.Decode32(afterTypeBytes.Span, out var decodedLength);

            result = new MaxStreamsFrame(maxStreams, type.ForBidirectional(), type.ForUnidirectional());
            remainings = afterTypeBytes.Slice(decodedLength);

            return true;
        }
    }
}
