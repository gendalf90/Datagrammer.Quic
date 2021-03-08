using Datagrammer.Quic.Protocol.Tls;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public static class PacketPayload
    {
        private const int SampleLength = 16;
        private const int SkipToSampleLength = 4;

        public static MemoryBuffer SlicePacketBytes(
            MemoryCursor cursor, 
            PacketFirstByte firstByte, 
            int startPacketOffset, 
            PacketNumber? largestAcknowledgedPacketNumber, 
            out PacketNumber packetNumber)
        {
            var readLength = cursor - startPacketOffset;
            var packetLength = cursor.DecodeVariable32();
            var packetNumberBytes = firstByte.SlicePacketNumberBytes(cursor);
            var payloadLength = packetLength - readLength - packetNumberBytes.Length;

            packetNumber = PacketNumber.Parse(packetNumberBytes.Span);

            if (largestAcknowledgedPacketNumber.HasValue)
            {
                packetNumber = packetNumber.DecodeByLargestAcknowledged(largestAcknowledgedPacketNumber.Value);
            }

            return cursor.Slice(payloadLength);
        }

        public static MemoryBuffer SliceLongProtectedPacketBytes(
            MemoryCursor cursor,
            IAead aead, 
            ICipher cipher,
            int startPacketOffset,
            PacketFirstByte firstByte,
            PacketNumber? largestAcknowledgedPacketNumber,
            out PacketNumber packetNumber)
        {
            var readLength = cursor - startPacketOffset;
            var packetLength = cursor.DecodeVariable32();
            var startPayloadOffset = cursor.AsOffset();

            cursor.Move(SkipToSampleLength);

            var sample = cursor.Move(SampleLength);
            var mask = cipher.CreateMask(sample.Span);

            cursor.Set(startPacketOffset);
            firstByte.Mask(mask).Write(cursor);
            cursor.Set(startPayloadOffset);

            var packetNumberBytes = firstByte.Mask(mask).SlicePacketNumberBytes(cursor);
            var headerLength = cursor - startPacketOffset;
            var headerBytes = cursor.Peek(-headerLength);
            var payloadLength = packetLength - readLength - packetNumberBytes.Length;
            var payload = cursor.Slice(payloadLength);
            var payloadBytes = cursor.Peek(-payloadLength);
            var tagBytes = cursor.Move(aead.TagLength);
            var encodedPacketNumber = PacketNumber.Parse(packetNumberBytes.Span, mask);

            encodedPacketNumber.Fill(packetNumberBytes.Span);

            packetNumber = largestAcknowledgedPacketNumber.HasValue
                ? encodedPacketNumber.DecodeByLargestAcknowledged(largestAcknowledgedPacketNumber.Value)
                : encodedPacketNumber;

            packetNumber.Decrypt(aead, payloadBytes.Span, tagBytes.Span, headerBytes.Span);

            return payload;
        }

        public static CursorWritingContext StartPacketWriting(MemoryCursor cursor, int startPacketOffset)
        {
            return new CursorWritingContext(cursor, startPacketOffset, cursor.AsOffset());
        }

        public static MemoryBuffer SliceShortProtectedPacketBytes(
            MemoryCursor cursor,
            IAead aead,
            ICipher cipher,
            int startPacketOffset,
            PacketFirstByte firstByte,
            PacketNumber largestAcknowledgedPacketNumber,
            out PacketNumber packetNumber)
        {
            var startPacketNumberOffset = cursor.AsOffset();

            cursor.Move(SkipToSampleLength);

            var sample = cursor.Move(SampleLength);
            var mask = cipher.CreateMask(sample.Span);

            cursor.Set(startPacketOffset);
            firstByte.Mask(mask).Write(cursor);
            cursor.Set(startPacketNumberOffset);

            var packetNumberBytes = firstByte.Mask(mask).SlicePacketNumberBytes(cursor);
            var headerLength = cursor - startPacketOffset;
            var headerBytes = cursor.Peek(-headerLength);
            var startPayloadOffset = cursor.AsOffset();

            cursor.MoveEnd();

            var tagBytes = cursor.Move(-aead.TagLength);
            var payloadLength = cursor - startPayloadOffset;
            var payloadBytes = cursor.Peek(-payloadLength);
            var payload = cursor.Slice(-payloadLength);
            var encodedPacketNumber = PacketNumber.Parse(packetNumberBytes.Span, mask);

            encodedPacketNumber.Fill(packetNumberBytes.Span);

            packetNumber = encodedPacketNumber.DecodeByLargestAcknowledged(largestAcknowledgedPacketNumber);

            packetNumber.Decrypt(aead, payloadBytes.Span, tagBytes.Span, headerBytes.Span);
            cursor.MoveEnd();

            return payload;
        }

        public static ShortProtectedWritingContext StartShortProtectedPacketWriting(
            MemoryCursor cursor,
            IAead aead,
            ICipher cipher,
            int startPacketOffset,
            PacketFirstByte firstByte,
            PacketNumber packetNumber,
            PacketNumber largestAcknowledgedPacketNumber)
        {
            return new ShortProtectedWritingContext(aead, cipher, cursor, startPacketOffset, cursor.AsOffset(), packetNumber, largestAcknowledgedPacketNumber, firstByte);
        }

        public static LongProtectedWritingContext StartLongProtectedPacketWriting(
            MemoryCursor cursor, 
            IAead aead, 
            ICipher cipher, 
            int startPacketOffset, 
            PacketFirstByte firstByte,
            PacketNumber packetNumber,
            PacketNumber? largestAcknowledgedPacketNumber)
        {
            return new LongProtectedWritingContext(aead, cipher, cursor, startPacketOffset, cursor.AsOffset(), packetNumber, largestAcknowledgedPacketNumber, firstByte);
        }

        public readonly ref struct CursorWritingContext
        {
            private readonly MemoryCursor cursor;
            private readonly int startPacketOffset;
            private readonly int toWriteLengthOffset;

            public CursorWritingContext(
                MemoryCursor cursor, 
                int startPacketOffset,
                int toWriteLengthOffset)
            {
                this.cursor = cursor;
                this.startPacketOffset = startPacketOffset;
                this.toWriteLengthOffset = toWriteLengthOffset;
            }

            public void Dispose()
            {
                var packetLength = cursor - startPacketOffset;
                var payloadLength = cursor - toWriteLengthOffset;
                var payload = cursor.Move(-payloadLength);

                Span<byte> payloadBuffer = stackalloc byte[payloadLength];

                payload.Span.CopyTo(payloadBuffer);
                cursor.EncodeVariable32(packetLength);
                payloadBuffer.CopyTo(cursor);
            }
        }

        public readonly ref struct ShortProtectedWritingContext
        {
            private readonly IAead aead;
            private readonly ICipher cipher;
            private readonly MemoryCursor cursor;
            private readonly int startPacketOffset;
            private readonly int startPayloadOffset;
            private readonly PacketNumber packetNumber;
            private readonly PacketNumber largestAcknowledgedPacketNumber;
            private readonly PacketFirstByte packetFirstByte;

            public ShortProtectedWritingContext(
                IAead aead,
                ICipher cipher,
                MemoryCursor cursor,
                int startPacketOffset,
                int startPayloadOffset,
                PacketNumber packetNumber,
                PacketNumber largestAcknowledgedPacketNumber,
                PacketFirstByte packetFirstByte)
            {
                this.aead = aead;
                this.cipher = cipher;
                this.cursor = cursor;
                this.startPacketOffset = startPacketOffset;
                this.startPayloadOffset = startPayloadOffset;
                this.packetNumber = packetNumber;
                this.largestAcknowledgedPacketNumber = largestAcknowledgedPacketNumber;
                this.packetFirstByte = packetFirstByte;
            }

            public void Dispose()
            {
                var payloadLength = cursor - startPayloadOffset;
                var payload = cursor.Move(-payloadLength);

                Span<byte> payloadBuffer = stackalloc byte[payloadLength];
                Span<byte> tagBuffer = stackalloc byte[aead.TagLength];

                payload.Span.CopyTo(payloadBuffer);

                var encodedPacketNumber = packetNumber.EncodeByLargestAcknowledged(largestAcknowledgedPacketNumber);
                var minPacketNumberLength = SkipToSampleLength - payloadLength;
                var packetNumberLength = minPacketNumberLength < 0
                    ? encodedPacketNumber.Write(cursor)
                    : encodedPacketNumber.Write(cursor, minPacketNumberLength);
                var startEncryptedPayloadOffset = cursor.AsOffset();
                var packetFirstByteWithNumberLength = packetFirstByte.SetPacketNumberLength(packetNumberLength);
                var packetNumberBytes = cursor.Peek(-packetNumberLength);
                var headerLength = cursor - startPacketOffset;
                var header = cursor.Move(-headerLength);

                packetFirstByteWithNumberLength.Write(cursor);
                cursor.Set(startEncryptedPayloadOffset);
                packetNumber.Encrypt(aead, payloadBuffer, tagBuffer, header.Span);
                payloadBuffer.CopyTo(cursor);
                tagBuffer.CopyTo(cursor);

                var endPacketOffset = cursor.AsOffset();

                cursor.Set(startPayloadOffset);
                cursor.Move(SkipToSampleLength);

                var sample = cursor.Move(SampleLength);
                var mask = cipher.CreateMask(sample.Span);

                encodedPacketNumber.Fill(packetNumberBytes.Span, mask);
                cursor.Set(startPacketOffset);
                packetFirstByteWithNumberLength.Mask(mask).Write(cursor);
                cursor.Set(endPacketOffset);
            }
        }

        public readonly ref struct LongProtectedWritingContext
        {
            private readonly IAead aead;
            private readonly ICipher cipher;
            private readonly MemoryCursor cursor;
            private readonly int startPacketOffset;
            private readonly int startPayloadOffset;
            private readonly PacketNumber packetNumber;
            private readonly PacketNumber? largestAcknowledgedPacketNumber;
            private readonly PacketFirstByte packetFirstByte;

            public LongProtectedWritingContext(
                IAead aead,
                ICipher cipher,
                MemoryCursor cursor,
                int startPacketOffset,
                int startPayloadOffset,
                PacketNumber packetNumber,
                PacketNumber? largestAcknowledgedPacketNumber,
                PacketFirstByte packetFirstByte)
            {
                this.aead = aead;
                this.cipher = cipher;
                this.cursor = cursor;
                this.startPacketOffset = startPacketOffset;
                this.startPayloadOffset = startPayloadOffset;
                this.packetNumber = packetNumber;
                this.largestAcknowledgedPacketNumber = largestAcknowledgedPacketNumber;
                this.packetFirstByte = packetFirstByte;
            }

            public void Dispose()
            {
                var payloadLength = cursor - startPayloadOffset;
                var payload = cursor.Peek(-payloadLength);

                Span<byte> payloadBuffer = stackalloc byte[payloadLength];
                Span<byte> tagBuffer = stackalloc byte[aead.TagLength];

                payload.Span.CopyTo(payloadBuffer);
                packetFirstByte.SlicePacketNumberBytes(cursor);

                var packetLength = cursor - startPacketOffset;

                cursor.Set(startPayloadOffset);
                cursor.EncodeVariable32(packetLength);

                var packetNumberBytes = packetFirstByte.SlicePacketNumberBytes(cursor);
                var encodedPacketNumber = largestAcknowledgedPacketNumber.HasValue
                    ? packetNumber.EncodeByLargestAcknowledged(largestAcknowledgedPacketNumber.Value)
                    : packetNumber;

                encodedPacketNumber.Fill(packetNumberBytes.Span);

                var headerLength = cursor - startPacketOffset;
                var header = cursor.Peek(-headerLength);

                packetNumber.Encrypt(aead, payloadBuffer, tagBuffer, header.Span);
                payloadBuffer.CopyTo(cursor);
                tagBuffer.CopyTo(cursor);

                var endPacketOffset = cursor.AsOffset();
                var encryptedLength = payloadBuffer.Length + tagBuffer.Length;
                var encryptedData = cursor.Peek(-encryptedLength);
                var sample = encryptedData.Slice(0, SampleLength);
                var mask = cipher.CreateMask(sample.Span);

                encodedPacketNumber.Fill(packetNumberBytes.Span, mask);
                cursor.Set(startPacketOffset);
                packetFirstByte.Mask(mask).Write(cursor);
                cursor.Set(endPacketOffset);
            }
        }
    }
}
