using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class Finished
    {
        public static bool TryParse(MemoryCursor cursor, out MemoryBuffer verifyData)
        {
            verifyData = new MemoryBuffer();

            if (!HandshakeType.TrySlice(cursor, HandshakeType.Finished))
            {
                return false;
            }

            verifyData = HandshakeLength.SliceBytes(cursor);

            return true;
        }

        public static bool TryParse(ref ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> verifyData)
        {
            verifyData = ReadOnlyMemory<byte>.Empty;

            if (!HandshakeType.TrySlice(ref bytes, HandshakeType.Finished))
            {
                return false;
            }

            verifyData = HandshakeLength.SliceHandshakeBytes(ref bytes);

            return true;
        }

        public static HandshakeLength.WritingContext StartWriting(ref Span<byte> bytes)
        {
            HandshakeType.Finished.WriteBytes(ref bytes);

            return HandshakeLength.StartWriting(ref bytes);
        }

        public static HandshakeLength.CursorWritingContext StartWriting(MemoryCursor cursor)
        {
            HandshakeType.Finished.WriteBytes(cursor);

            return HandshakeLength.StartWriting(cursor);
        }
    }
}
