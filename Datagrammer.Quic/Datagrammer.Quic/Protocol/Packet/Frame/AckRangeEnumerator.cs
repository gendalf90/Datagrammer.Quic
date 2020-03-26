using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public struct AckRangeEnumerator
    {
        private readonly PacketNumber largestAcknowledged;

        private AckRange? currentRange;
        private bool isFirstRangeRead;
        private ReadOnlyMemory<byte> remainings;
        private PacketNumber currentSmallest;

        internal AckRangeEnumerator(PacketNumber largestAcknowledged, ReadOnlyMemory<byte> bytes)
        {
            this.largestAcknowledged = largestAcknowledged;

            currentRange = null;
            isFirstRangeRead = false;
            remainings = bytes;
            currentSmallest = largestAcknowledged;
        }

        public AckRange Current => currentRange ?? throw new ArgumentOutOfRangeException(nameof(Current));

        public bool MoveNext()
        {
            ClearCurrentRange();

            if (NeedReadFirstRange())
            {
                return TryReadFirstRange();
            }

            return TryReadRange();
        }

        private void ClearCurrentRange()
        {
            currentRange = null;
        }

        private bool NeedReadFirstRange()
        {
            return !isFirstRangeRead;
        }

        private bool TryReadFirstRange()
        {
            if(!VariableLengthEncoding.TryDecode(remainings.Span, out var firstRangeValue, out var decodedLength))
            {
                return false;
            }

            currentSmallest = new PacketNumber(largestAcknowledged.Number - firstRangeValue);
            currentRange = new AckRange(currentSmallest, largestAcknowledged);
            remainings = remainings.Slice(decodedLength);
            isFirstRangeRead = true;

            return true;
        }

        private bool TryReadRange()
        {
            if (!VariableLengthEncoding.TryDecode(remainings.Span, out var gapValue, out var decodedLength))
            {
                return false;
            }

            if(gapValue + 2 > currentSmallest.Number)
            {
                return false;
            }

            var currentLargest = new PacketNumber(currentSmallest.Number - gapValue - 2);
            var afterGapRemainings = remainings.Slice(decodedLength);

            if (!VariableLengthEncoding.TryDecode(afterGapRemainings.Span, out var rangeValue, out decodedLength))
            {
                return false;
            }

            if(rangeValue > currentLargest.Number)
            {
                return false;
            }

            currentSmallest = new PacketNumber(currentLargest.Number - rangeValue);
            currentRange = new AckRange(currentSmallest, currentLargest);
            remainings = afterGapRemainings.Slice(decodedLength);

            return true;
        }
    }
}
