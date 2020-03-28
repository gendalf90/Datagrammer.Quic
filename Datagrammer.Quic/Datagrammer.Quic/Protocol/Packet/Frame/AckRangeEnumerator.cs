using Datagrammer.Quic.Protocol.Error;
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

            if(IsEmpty())
            {
                return false;
            }

            if (NeedReadFirstRange())
            {
                ReadFirstRange();
            }
            else
            {
                ReadRange();
            }

            return true;
        }

        private bool IsEmpty()
        {
            return remainings.IsEmpty;
        }

        private void ClearCurrentRange()
        {
            currentRange = null;
        }

        private bool NeedReadFirstRange()
        {
            return !isFirstRangeRead;
        }

        private void ReadFirstRange()
        {
            var firstRangeValue = VariableLengthEncoding.Decode(remainings.Span, out var decodedLength);

            currentSmallest = new PacketNumber(largestAcknowledged.Number - firstRangeValue);
            currentRange = new AckRange(currentSmallest, largestAcknowledged);
            remainings = remainings.Slice(decodedLength);
            isFirstRangeRead = true;
        }

        private void ReadRange()
        {
            var gapValue = VariableLengthEncoding.Decode(remainings.Span, out var decodedLength);

            if (gapValue + 2 > currentSmallest.Number)
            {
                throw new EncodingException();
            }

            var currentLargest = new PacketNumber(currentSmallest.Number - gapValue - 2);
            var afterGapRemainings = remainings.Slice(decodedLength);
            var rangeValue = VariableLengthEncoding.Decode(afterGapRemainings.Span, out decodedLength);

            if(rangeValue > currentLargest.Number)
            {
                throw new EncodingException();
            }

            currentSmallest = new PacketNumber(currentLargest.Number - rangeValue);
            currentRange = new AckRange(currentSmallest, currentLargest);
            remainings = afterGapRemainings.Slice(decodedLength);
        }
    }
}
