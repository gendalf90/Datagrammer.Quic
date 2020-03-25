using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct AckFrame
    {
        private AckFrame(AckDelay delay, 
                         AckRanges ranges,
                         EcnCounts? ecnFeedback)
        {
            Delay = delay;
            Ranges = ranges;
            EcnFeedback = ecnFeedback;
        }

        public AckDelay Delay { get; }

        public AckRanges Ranges { get; }

        public EcnCounts? EcnFeedback { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out AckFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new AckFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            if(!FrameType.TryParseFrameType(bytes, out var type, out var afterTypeRemainings))
            {
                return false;
            }

            if(type != 2 || type != 3)
            {
                return false;
            }

            var hasEcnFeedback = type == 3;

            if(!PacketNumber.TryParse(afterTypeRemainings, out var largestAcknowledgedPacketNumber, out var afterLargestNumberBytes))
            {
                return false;
            }

            if(!AckDelay.TryParse(afterLargestNumberBytes, out var delay, out var afterDelayBytes))
            {
                return false;
            }

            if(!VariableLengthEncoding.TryDecode32(afterDelayBytes.Span, out var rangesCount, out var rangesCountDecodedLength))
            {
                return false;
            }

            var afterRangesCountBytes = afterDelayBytes.Slice(rangesCountDecodedLength);
            var rangesCountPlusFirstRange = rangesCount + 1;

            if(!TrySliceVariables(afterRangesCountBytes, rangesCountPlusFirstRange, out var afterRangesBytes))
            {
                return false;
            }

            var rangesBytes = afterRangesCountBytes.Slice(0, afterRangesCountBytes.Length - afterRangesBytes.Length);
            
            if(!EcnCounts.TryParse(afterRangesBytes, out var ecnCounts, out var afterEcnBytes) && hasEcnFeedback)
            {
                return false;
            }

            var ranges = new AckRanges(largestAcknowledgedPacketNumber, rangesBytes);
            var ecnFeedback = hasEcnFeedback ? ecnCounts : new EcnCounts?();
            var remainingBytes = hasEcnFeedback ? afterEcnBytes : afterRangesBytes;

            result = new AckFrame(delay, ranges, ecnFeedback);
            remainings = remainingBytes;

            return true;
        }

        private static bool TrySliceVariables(ReadOnlyMemory<byte> bytes, int count, out ReadOnlyMemory<byte> remainings)
        {
            remainings = bytes;

            for(int i = 0; i < count; i++)
            {
                if(!TrySliceVariable(remainings, out remainings))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool TrySliceVariable(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            remainings = ReadOnlyMemory<byte>.Empty;

            if(!VariableLengthEncoding.TryDecode(bytes.Span, out var value, out int decodedLength))
            {
                return false;
            }

            remainings = bytes.Slice(decodedLength);

            return true;
        }
    }
}
