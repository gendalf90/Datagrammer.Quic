using Datagrammer.Quic.Protocol.Error;
using Datagrammer.Quic.Protocol.Tls;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public static class PacketPayload
    {
        private const int SampleLength = 16;
        private const int SkipToSampleLength = 4;

        public static ReadOnlyMemory<byte> SlicePacketBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> afterPacketBytes)
        {
            var length = VariableLengthEncoding.Decode32(bytes.Span, out var decodedBytesLength);
            var afterLengthBytes = bytes.Slice(decodedBytesLength);

            if(afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            afterPacketBytes = afterLengthBytes.Slice(length);

            return afterLengthBytes.Slice(0, length);
        }

        public static MemoryBuffer SlicePacketBytes(MemoryCursor cursor, PacketFirstByte firstByte, int startPacketOffset, out PacketNumber packetNumber)
        {
            var readLength = cursor - startPacketOffset;
            var packetLength = cursor.DecodeVariable32();
            var packetNumberBytes = firstByte.SlicePacketNumberBytes(cursor);
            var payloadLength = packetLength - readLength - packetNumberBytes.Length;

            packetNumber = PacketNumber.Parse(packetNumberBytes.Span);

            return cursor.Slice(payloadLength);
        }

        public static MemoryBuffer SliceLongProtectedPacketBytes(
            MemoryCursor cursor,
            IAead aead, 
            ICipher cipher,
            int startPacketOffset,
            PacketFirstByte firstByte,  
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

            PacketNumber.Mask(packetNumberBytes.Span, mask);

            packetNumber = PacketNumber.Parse(packetNumberBytes.Span);

            packetNumber.Decrypt(aead, payloadBytes.Span, tagBytes.Span, headerBytes.Span);

            return payload;
        }

        public static WritingContext StartPacketWriting(ref Span<byte> bytes)
        {
            if(bytes.Length < 4)
            {
                throw new EncodingException();
            }

            var context = new WritingContext(bytes);

            bytes = bytes.Slice(4);

            return context;
        }

        public static CursorWritingContext StartPacketWriting(MemoryCursor cursor, int startPacketOffset)
        {
            return new CursorWritingContext(cursor, startPacketOffset, cursor.AsOffset());
        }

        public static LongProtectedWritingContext StartLongProtectedPacketWriting(
            MemoryCursor cursor, 
            IAead aead, 
            ICipher cipher, 
            int startPacketOffset, 
            PacketFirstByte firstByte,
            PacketNumber packetNumber)
        {
            return new LongProtectedWritingContext(aead, cipher, cursor, startPacketOffset, cursor.AsOffset(), packetNumber, firstByte);
        }

        public readonly ref struct WritingContext
        {
            private readonly Span<byte> start;

            public WritingContext(Span<byte> start)
            {
                this.start = start;
            }

            public void Complete(ref Span<byte> bytes)
            {
                var offset = start.Length - bytes.Length;

                if (offset < 4)
                {
                    throw new EncodingException();
                }

                var payloadLength = offset - 4;

                VariableLengthEncoding.Encode(start, (ulong)payloadLength, out var encodedLength);

                var afterLengthBytes = start.Slice(encodedLength);
                var payload = start.Slice(4, payloadLength);

                payload.CopyTo(afterLengthBytes);

                bytes = start.Slice(encodedLength + payloadLength);
            }
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

        public readonly ref struct LongProtectedWritingContext
        {
            private readonly IAead aead;
            private readonly ICipher cipher;
            private readonly MemoryCursor cursor;
            private readonly int startPacketOffset;
            private readonly int startPayloadOffset;
            private readonly PacketNumber packetNumber;
            private readonly PacketFirstByte packetFirstByte;

            public LongProtectedWritingContext(
                IAead aead,
                ICipher cipher,
                MemoryCursor cursor,
                int startPacketOffset,
                int startPayloadOffset,
                PacketNumber packetNumber,
                PacketFirstByte packetFirstByte)
            {
                this.aead = aead;
                this.cipher = cipher;
                this.cursor = cursor;
                this.startPacketOffset = startPacketOffset;
                this.startPayloadOffset = startPayloadOffset;
                this.packetNumber = packetNumber;
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

                var packetNumberBytes = packetFirstByte.SlicePacketNumberBytes(cursor).Span;

                packetNumber.Fill(packetNumberBytes);

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

                packetNumber.Fill(packetNumberBytes);
                PacketNumber.Mask(packetNumberBytes, mask);
                cursor.Set(startPacketOffset);
                packetFirstByte.Mask(mask).Write(cursor);
                cursor.Set(endPacketOffset);
            }
        }
    }
}
