﻿using Datagrammer.Quic.Protocol.Error;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct CryptoFrame
    {
        private CryptoFrame(int offset, MemoryBuffer data)
        {
            if(offset < 0)
            {
                throw new EncodingException();
            }

            Offset = offset;
            Data = data;
        }

        public int Offset { get; }

        public MemoryBuffer Data { get; }

        public static bool TryParse(MemoryCursor cursor, out CryptoFrame result)
        {
            result = new CryptoFrame();

            if (!FrameType.TrySlice(cursor, FrameType.Crypto))
            {
                return false;
            }

            var offset = cursor.DecodeVariable32();
            var data = VariableLengthPayload.SliceBytes(cursor);

            result = new CryptoFrame(offset, data);

            return true;
        }

        public static VariableLengthPayload.CursorWritingContext StartWriting(MemoryCursor cursor, int offset)
        {
            FrameType.Crypto.Write(cursor);

            cursor.EncodeVariable32(offset);

            return VariableLengthPayload.StartWriting(cursor);
        }
    }
}
