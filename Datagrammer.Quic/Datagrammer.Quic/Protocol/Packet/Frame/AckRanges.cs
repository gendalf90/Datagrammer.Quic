using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct AckRanges
    {
        private readonly ReadOnlyMemory<byte> bytes;

        public AckRanges(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public Enumerator GetEnumerator()
        {
            return new Enumerator(bytes);
        }

        public ref struct Enumerator
        {
            private AckRange? currentRange;
            private bool isGapNext;
            private ReadOnlyMemory<byte> remainings;

            public Enumerator(ReadOnlyMemory<byte> bytes)
            {
                currentRange = null;
                isGapNext = false;
                remainings = bytes;
            }

            public AckRange Current => currentRange ?? throw new ArgumentOutOfRangeException(nameof(Current));

            public bool MoveNext()
            {
                ClearCurrentRange();

                if (IsEmpty())
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

            private int ReadLength()
            {
                var length = VariableLengthEncoding.Decode(remainings.Span, out var decodedLength);

                if (length > int.MaxValue)
                {
                    throw new EncodingException();
                }

                remainings = remainings.Slice(decodedLength);

                return (int)length;
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
}
