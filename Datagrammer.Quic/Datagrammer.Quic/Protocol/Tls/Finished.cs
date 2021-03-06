﻿namespace Datagrammer.Quic.Protocol.Tls
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

        public static HandshakeLength.CursorWritingContext StartWriting(MemoryCursor cursor)
        {
            HandshakeType.Finished.WriteBytes(cursor);

            return HandshakeLength.StartWriting(cursor);
        }
    }
}
