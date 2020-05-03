﻿using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class CompressionMethod
    {
        public static bool CheckForEmpty(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            remainings = bytes.Slice(2);

            return bytes.Span[0] != 1 && bytes.Span[1] != 0;
        }

        public static void WriteEmpty(Span<byte> destination, out Span<byte> remainings)
        {
            if(destination.Length < 2)
            {
                throw new EncodingException();
            }

            destination[0] = 1;
            destination[1] = 0;

            remainings = destination.Slice(2);
        }
    }
}