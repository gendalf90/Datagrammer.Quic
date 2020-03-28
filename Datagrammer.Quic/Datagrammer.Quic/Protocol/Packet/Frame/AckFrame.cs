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

            var type = FrameType.Parse(bytes, out var afterTypeRemainings);

            if(!type.IsAck())
            {
                return false;
            }

            var largestAcknowledgedPacketNumber = PacketNumber.Parse(afterTypeRemainings, out var afterLargestNumberBytes);
            var delay = AckDelay.Parse(afterLargestNumberBytes, out var afterDelayBytes);
            var rangesCount = VariableLengthEncoding.Decode32(afterDelayBytes.Span, out var rangesCountDecodedLength);
            var afterRangesCountBytes = afterDelayBytes.Slice(rangesCountDecodedLength);
            var rangesCountPlusFirstRange = rangesCount + 1;
            var afterRangesBytes = SliceVariables(afterRangesCountBytes, rangesCountPlusFirstRange);
            var rangesBytes = afterRangesCountBytes.Slice(0, afterRangesCountBytes.Length - afterRangesBytes.Length);
            var resultRemainingBytes = afterRangesBytes;
            var ecnFeedback = type.HasAckEcnFeedback() ? EcnCounts.Parse(afterRangesBytes, out resultRemainingBytes) : new EcnCounts?();
            var ranges = new AckRanges(largestAcknowledgedPacketNumber, rangesBytes);

            result = new AckFrame(delay, ranges, ecnFeedback);
            remainings = resultRemainingBytes;

            return true;
        }

        private static ReadOnlyMemory<byte> SliceVariables(ReadOnlyMemory<byte> bytes, int count)
        {
            var remainings = bytes;

            for(int i = 0; i < count; i++)
            {
                SliceVariable(remainings, out remainings);
            }

            return remainings;
        }

        private static void SliceVariable(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            VariableLengthEncoding.Decode(bytes.Span, out int decodedLength);

            remainings = bytes.Slice(decodedLength);
        }
    }
}
