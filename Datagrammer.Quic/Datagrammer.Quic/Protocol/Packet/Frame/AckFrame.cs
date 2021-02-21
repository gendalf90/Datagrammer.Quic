using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    //можно не хранить списки подтвержденных номеров пакетов, а только один - последний с самым большим номером
    //обрабатывать полученные параллельно и всегда слать gap'ы - они закроются из ответов параллельных обработчиков
    public readonly struct AckFrame
    {
        private AckFrame(AckDelay delay,
                         PacketNumber largestAcknowledged,
                         AckRanges ranges,
                         AckEcnCounts? ecnFeedback)
        {
            Delay = delay;
            LargestAcknowledged = largestAcknowledged;
            Ranges = ranges;
            EcnFeedback = ecnFeedback;
        }

        public AckDelay Delay { get; }

        public PacketNumber LargestAcknowledged { get; }

        public AckRanges Ranges { get; }

        public AckEcnCounts? EcnFeedback { get; }

        public static bool TryParse(MemoryCursor cursor, out AckFrame result)
        {
            result = new AckFrame();

            var type = FrameType.Peek(cursor);

            if(!type.IsAck)
            {
                return false;
            }

            type.Slice(cursor);

            var largestAcknowledged = PacketNumber.ParseVariable(cursor);
            var delay = AckDelay.Parse(cursor);
            var rangesCount = cursor.DecodeVariable32();
            var ranges = SliceRanges(cursor, rangesCount + 1);
            var ecnFeedback = type.HasAckEcnFeedback ? AckEcnCounts.Parse(cursor) : new AckEcnCounts?();

            result = new AckFrame(delay, largestAcknowledged, ranges, ecnFeedback);

            return true;
        }

        private static AckRanges SliceRanges(MemoryCursor cursor, int count)
        {
            var startOffset = cursor.AsOffset();

            for (int i = 0; i < count; i++)
            {
                SliceRange(cursor);
            }

            var bytes = cursor.Peek(startOffset - cursor);

            return new AckRanges(bytes);
        }

        private static void SliceRange(MemoryCursor cursor)
        {
            var bytes = cursor.PeekEnd();
            var rangeBytes = VariableLengthEncoding.Slice(bytes.Span);

            cursor.Move(rangeBytes.Length);
        }

        public static WritingContext StartWriting(MemoryCursor cursor, 
                                                  AckDelay delay, 
                                                  PacketNumber largestAcknowledged,
                                                  int beforLargestAcknowledgedLength,
                                                  AckEcnCounts? ecnFeedback = null)
        {
            if (beforLargestAcknowledgedLength < 0)
            {
                throw new EncodingException();
            }

            FrameType
                .CreateAck(ecnFeedback.HasValue)
                .Write(cursor);

            largestAcknowledged.WriteVariable(cursor);
            delay.Write(cursor);

            var startPayloadOffset = cursor.AsOffset();

            cursor.EncodeVariable32(beforLargestAcknowledgedLength);

            var startRangesOffset = cursor.AsOffset();

            return new WritingContext(cursor, ecnFeedback, startPayloadOffset, startRangesOffset);
        }

        public readonly ref struct WritingContext
        {
            private readonly MemoryCursor cursor;
            private readonly AckEcnCounts? ecnFeedback;
            private readonly int startPayloadOffset;
            private readonly int startRangesOffset;

            public WritingContext(MemoryCursor cursor, 
                                  AckEcnCounts? ecnFeedback,
                                  int startPayloadOffset,
                                  int startRangesOffset)
            {
                this.cursor = cursor;
                this.ecnFeedback = ecnFeedback;
                this.startPayloadOffset = startPayloadOffset;
                this.startRangesOffset = startRangesOffset;
            }

            public WritingContext WriteGap(int length, int offset)
            {
                if (length < 1)
                {
                    throw new EncodingException();
                }

                if (offset < 0)
                {
                    throw new EncodingException();
                }

                cursor.EncodeVariable32(length - 1);
                cursor.EncodeVariable32(offset);

                return this;
            }

            public void Finish()
            {
                var currentOffset = cursor.AsOffset();
                var rangesLength = currentOffset - startRangesOffset;
                var rangesCount = 0;

                using (cursor.WithLimit(-rangesLength))
                {
                    cursor.MoveStart();

                    while (!cursor.IsEnd())
                    {
                        SliceRange(cursor);

                        rangesCount++;
                    }
                }

                var payloadLength = currentOffset - startPayloadOffset;
                var payloadBytes = cursor.Move(-payloadLength);

                Span<byte> payloadBuffer = stackalloc byte[payloadLength];

                payloadBytes.Span.CopyTo(payloadBuffer);
                cursor.EncodeVariable32(rangesCount);
                payloadBuffer.CopyTo(cursor);

                if (ecnFeedback.HasValue)
                {
                    ecnFeedback.Value.Write(cursor);
                }
            }
        }
    }
}
