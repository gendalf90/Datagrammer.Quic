using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public struct AckRangeEnumerator
    {
        private AckRange? currentRange;
        private bool isGapNext;
        private ReadOnlyMemory<byte> remainings;

        internal AckRangeEnumerator(ReadOnlyMemory<byte> bytes)
        {
            currentRange = null;
            isGapNext = false;
            remainings = bytes;
        }

        public AckRange Current => currentRange ?? throw new ArgumentOutOfRangeException(nameof(Current));

        public bool MoveNext()
        {
            ClearCurrentRange();

            if(IsEmpty())
            {
                return false;
            }

            if (IsAckRangeReading())
            {
                ReadAck();
            }
            else
            {
                ReadGap();
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

        private bool IsAckRangeReading()
        {
            return !isGapNext;
        }

        private ulong ReadLength()
        {
            var length = VariableLengthEncoding.Decode(remainings.Span, out var decodedLength);

            remainings = remainings.Slice(decodedLength);

            return length;
        }

        private void ReadAck()
        {
            var ackLength = ReadLength();

            currentRange = new AckRange(true, false, ackLength);
            isGapNext = true;
        }

        private void ReadGap()
        {
            var gapLength = ReadLength();

            currentRange = new AckRange(false, true, gapLength + 1);
            isGapNext = false;
        }
    }
}
