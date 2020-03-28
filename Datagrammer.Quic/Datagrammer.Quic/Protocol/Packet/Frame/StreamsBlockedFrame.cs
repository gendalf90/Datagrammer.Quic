using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct StreamsBlockedFrame
    {
        private StreamsBlockedFrame(int streamLimit,
                                    bool forBidirectional,
                                    bool forUnidirectional)
        {
            StreamLimit = streamLimit;
            ForBidirectional = forBidirectional;
            ForUnidirectional = forUnidirectional;
        }

        public int StreamLimit { get; }

        public bool ForBidirectional { get; }

        public bool ForUnidirectional { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out StreamsBlockedFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new StreamsBlockedFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsStreamsBlocked())
            {
                return false;
            }

            var streamLimit = VariableLengthEncoding.Decode32(afterTypeBytes.Span, out var decodedLength);

            result = new StreamsBlockedFrame(streamLimit, type.ForBidirectional(), type.ForUnidirectional());
            remainings = afterTypeBytes.Slice(decodedLength);

            return true;
        }
    }
}
