using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CipherSuite
    {
        private readonly ReadOnlyMemory<byte> bytes;
        private readonly bool isList;

        private CipherSuite(ReadOnlyMemory<byte> bytes, bool isList)
        {
            this.bytes = bytes;
            this.isList = isList;
        }

        public static CipherSuite CreateFromList(params Cipher[] ciphers)
        {
            Span<byte> buffer = stackalloc byte[TlsBuffer.MaxRecordSize];
            Span<byte> cursor = buffer;

            for(int i = 0; i < ciphers.Length; i++)
            {
                ciphers[i].WriteBytes(ref cursor);
            }

            return new CipherSuite(buffer.Slice(0, buffer.Length - cursor.Length).ToArray(), true);
        }

        public static CipherSuite SupportedList { get; } = CreateFromList(Cipher.TLS_AES_128_GCM_SHA256);

        public bool TrySelectOneCipherFrom(CipherSuite cipherSuite, out CipherSuite result)
        {
            var remainings = bytes;

            while (TryParseOneCipher(remainings, out var cipher, out result, out remainings))
            {
                if(cipherSuite.Contains(cipher))
                {
                    return true;
                }
            }
            
            return false;
        }

        private bool TryParseOneCipher(ReadOnlyMemory<byte> data, out Cipher cipher, out CipherSuite suite, out ReadOnlyMemory<byte> remainings)
        {
            cipher = new Cipher();
            suite = new CipherSuite();
            remainings = data;

            if(data.IsEmpty)
            {
                return false;
            }

            cipher = Cipher.Parse(data, out remainings);
            suite = new CipherSuite(bytes.Slice(0, bytes.Length - remainings.Length), false);

            return true;
        }

        private bool Contains(Cipher cipher)
        {
            var currentRemainings = bytes;

            while (!currentRemainings.IsEmpty)
            {
                if(Cipher.Parse(currentRemainings, out currentRemainings) == cipher)
                {
                    return true;
                }
            }

            return false;
        }

        public bool HasAnyFrom(CipherSuite cipherSuite)
        {
            return TrySelectOneCipherFrom(cipherSuite, out _);
        }

        public static CipherSuite ParseList(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var data = ByteVector.SliceVectorBytes(bytes, 2..ushort.MaxValue, out remainings);

            return new CipherSuite(data, true);
        }

        public static CipherSuite Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            Cipher.Parse(bytes, out remainings);

            return new CipherSuite(bytes.Slice(0, bytes.Length - remainings.Length), false);
        }

        public void Write(ref Span<byte> destination)
        {
            if(isList)
            {
                WriteVector(ref destination);
            }
            else
            {
                WriteBytes(ref destination);
            }
        }

        public void WriteBytes(ref Span<byte> destination)
        {
            if (!bytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(bytes.Length);
        }

        private void WriteVector(ref Span<byte> destination)
        {
            var vectorContext = ByteVector.StartVectorWriting(ref destination, 2..ushort.MaxValue);

            WriteBytes(ref destination);

            vectorContext.Complete(ref destination);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
