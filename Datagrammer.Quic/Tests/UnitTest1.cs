using Datagrammer;
using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Packet;
using Datagrammer.Quic.Protocol.Packet.Frame;
using Datagrammer.Quic.Protocol.Tls;
using Datagrammer.Quic.Protocol.Tls.Extensions;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Datagrammer.Quic.Protocol.Tls.Ciphers;
using AtlasRhythm.Cryptography.Aeads;

namespace Tests
{
    public class UnitTest1
    {
        //[Fact]
        public void Test1()
        {
            var buff = new byte[PacketBuffer.MaxPacketSize];
            var pBuff = Utils.ParseHexString("060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001ffa500320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff");
            var hBuff = Utils.ParseHexString("c3ff000020088394c8f03e5157080000449e00000002");

            Array.Resize(ref pBuff, 1162);
            Array.Copy(hBuff, buff, hBuff.Length);
            Array.Copy(pBuff, 0, buff, hBuff.Length, pBuff.Length);
            Array.Resize(ref buff, hBuff.Length + pBuff.Length);

            var encryptedBuff = new byte[PacketBuffer.MaxPacketSize];
            var aead = Cipher.TLS_AES_128_GCM_SHA256.CreateAead(Utils.ParseHexString("6b26114b9cba2b63a9e8dd4f"), Utils.ParseHexString("175257a31eb09dea9366d8bb79ad80ba"));
            //var token = aead.StartEncryption(pBuff, encryptedBuff);
            //token.UseSequenceNumber(2);
            //token.UseAssociatedData(hBuff);
            //aead.Finish(token);
            //var encryptedHex = Utils.ToHexString(token.Result.ToArray());

            var c = new MemoryCursor(buff);
            var res1 = InitialPacket.TryParse(c, out var p);
            using (p.Payload.SetCursor(c))
            {
                var res2 = CryptoFrame.TryParse(c, out var f);
            }
            var res3 = c.IsEnd();

            var buffer = new byte[PacketBuffer.MaxPacketSize];
            var cursor = new MemoryCursor(buffer);

            using (InitialPacket.StartWriting(
                cursor,
                PacketVersion.CreateByDraft(29),
                PacketConnectionId.Generate(),
                PacketConnectionId.Generate(),
                PacketNumber.Initial, 
                PacketToken.Empty))
            {
                using (CryptoFrame.StartWriting(cursor, 0))
                {
                    using (ClientHello.StartWriting(cursor, HandshakeRandom.Generate(), Cipher.Supported, SessionId.Generate()))
                    {
                        using (cursor.StartSupportedGroupsWriting())
                        {
                            foreach(var group in NamedGroup.Supported.Span)
                            {
                                group.WriteBytes(cursor);
                            }
                        }

                        using (cursor.StartSignatureAlgorithmsWriting())
                        {
                            foreach(var scheme in SignatureScheme.Supported.Span)
                            {
                                scheme.WriteBytes(cursor);
                            }
                        }

                        using (cursor.StartKeySharesWriting())
                        {
                            using (KeyShareEntry.StartWriting(cursor, NamedGroup.X25519))
                            {
                                Utils.ParseHexString("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254").CopyTo(cursor);
                            }
                        }

                        using (cursor.StartPskKeyExchangeModesWriting())
                        {
                            PskKeyExchangeMode.PskDheKe.WriteBytes(cursor);
                        }

                        using (cursor.StartSupportedVersionsWriting())
                        {
                            ProtocolVersion.Tls13.WriteBytes(cursor);
                        }

                        cursor.StartTransportParametersWriting().Dispose();
                    }

                    for (int i = 0; i < 1000; i++)
                    {
                        PaddingFrame.WriteBytes(cursor);
                    }
                }
            }

            var t = Utils.ParseHexString("c0ff00001d08d0076f25b832934b0841f39c4f6381d72e0044ba00060041060100010203036e3828a258f4a7488d105acd6da670a41b28c2b601c58c4530486df585ec54a6000006130213011303010000d30033004700450017004104e46de65fb3e4fa258e1f03c551fa6a4507411e09bdc32e4dc597084db1852caf9d5b783243ebc748bf644ca31e108f4fdea2c19ae3c94ad99714dfa38a6a244500000021001f00001c68747470332d746573742e6c6974657370656564746563682e636f6d0010000800060568332d3239002b0003020304000d000a00080804040304010201000a000600040017001dffa5002d050480004000070480004000040480008000080101090103010267100e0104030245c00f0841f39c4f6381d72e002d000302000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

            var client = new UdpClient(0);
            var endPoint = new IPEndPoint(IPAddress.Parse("52.55.120.73"), 443);

            client.Send(t, t.Length, endPoint);

            IPEndPoint ep = null;
            var response = client.Receive(ref ep);

            var h1 = Utils.ToHexString(response);

            cursor = new MemoryCursor(response);

            var result = InitialPacket.TryParse(cursor, out var packet);

            using (packet.Payload.SetCursor(cursor))
            {
                var h2 = Utils.ToHexString(cursor.PeekEnd().ToArray());

                CryptoFrame.TryParse(cursor, out var cryptoFrame);

                using (cryptoFrame.Data.SetCursor(cursor))
                {
                    ServerHello.TryParse(cursor, out var sh);
                }
            }

            Assert.True(true);

            //var snBuff = new byte[100];
            //var snIter = snBuff.AsSpan();
            //ServerNameExtension.WriteHostName(ref snIter, "example.ulfheim.net");
            //var snResult = Parse(snBuff.AsSpan().Slice(0, snBuff.Length - snIter.Length).ToArray());

            //var keyShareBuff = new byte[1000];
            //var keyShareSpan = keyShareBuff.AsSpan();
            //var privateKey = Parse("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
            //var publicKey = NamedGroup.X25519.GeneratePublicKey(privateKey);
            //KeyShareExtension.WriteClientEntry(ref keyShareSpan, NamedGroup.X25519, publicKey);
            //var keyShareData = Parse(keyShareBuff.AsSpan().Slice(0, keyShareBuff.Length - keyShareSpan.Length).ToArray());

            //var secret = Parse("ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea");
            //var hash = Parse("22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b");
            //var expected = Parse("976017a77ae47f1658e28f7085fe37d149d1e9c91f56e1aebbe0c6bb054bd92b");

            //var verifyData = Hash.Sha256.CreateVerifyData(secret, hash);
            //var result = verifyData.Span.SequenceEqual(expected);

            //var bytes = GetData();

            //InitialPacket.TryParse(bytes, out var initial, out var remainings);

            //CryptoFrame.TryParse(initial.Payload, out var crypto, out var afterCrypto);

            //ClientHello.TryParse(crypto.Data, out var hello, out var afterHello);

            //KeyShareExtension.TryParse(hello.Payload, out var keyShare, out var afterKeyShare);

            //var unknownBytes = UnknownExtension.SliceBytes(afterKeyShare, out var afterUnknown);

            //AlpnExtension.TryParse(afterUnknown, out var alpn, out var afterAlpn);

            //SupportedVersionExtension.TryParse(afterAlpn, out var supportedVersion, out var afterSupportedVersion);

            //SignatureAlgorithmsExtension.TryParse(afterSupportedVersion, out var signatureAlgorithms, out var afterSignatureAlgorithms);

            //SupportedGroupsExtension.TryParse(afterSignatureAlgorithms, out var supportedGroups, out var afterSupportedGroups);

            //TransportParametersExtension.TryParse(afterSupportedGroups, out var transportParametersExtension, out var afterTransportParametersExtension);

            //PskKeyExchangeModesExtension.TryParse(afterTransportParametersExtension, out var pskKeyExchangeModes, out var afterPsk);

            ////----------------------------------------------------------------

            //var buffer = new byte[65000];
            //var destination = buffer.AsSpan();

            //var initialContext = InitialPacket.StartWriting(ref destination, initial.Version, initial.DestinationConnectionId, initial.SourceConnectionId, initial.Number, initial.Token);
            //var cryptoContext = CryptoFrame.StartWriting(ref destination, 0);
            //var clientHelloContext = ClientHello.StartWriting(ref destination, hello.Random, hello.CipherSuite, hello.SessionId);

            //keyShare.WriteBytes(ref destination);

            //unknownBytes.Span.CopyTo(destination);
            //destination = destination.Slice(unknownBytes.Length);

            //alpn.WriteBytes(ref destination);

            //supportedVersion.WriteBytes(ref destination);

            //signatureAlgorithms.WriteBytes(ref destination);

            //supportedGroups.WriteBytes(ref destination);

            //var transportParametersContext = TransportParametersExtension.StartWriting(ref destination);
            //transportParametersExtension.Data.Span.CopyTo(destination);
            //destination = destination.Slice(transportParametersExtension.Data.Length);
            //transportParametersContext.Complete(ref destination);

            //pskKeyExchangeModes.WriteBytes(ref destination);

            //clientHelloContext.Complete(ref destination);
            //cryptoContext.Complete(ref destination);

            //for (int i = 0; i < 1000; i++)
            //{
            //    PaddingFrame.WriteBytes(ref destination);
            //}

            //initialContext.Complete(ref destination);

            ////----------------------------------------------------------------

            //InitialPacket.TryParse(buffer.ToArray(), out var initial1, out var remainings1);

            //CryptoFrame.TryParse(initial1.Payload, out var crypto1, out var afterCrypto1);

            //ClientHello.TryParse(crypto1.Data, out var hello1, out var afterHello1);

            //KeyShareExtension.TryParse(hello1.Payload, out var keyShare1, out var afterKeyShare1);

            //var unknownBytes1 = UnknownExtension.SliceBytes(afterKeyShare1, out var afterUnknown1);

            //AlpnExtension.TryParse(afterUnknown1, out var alpn1, out var afterAlpn1);

            //SupportedVersionExtension.TryParse(afterAlpn1, out var supportedVersion1, out var afterSupportedVersion1);

            //SignatureAlgorithmsExtension.TryParse(afterSupportedVersion1, out var signatureAlgorithms1, out var afterSignatureAlgorithms1);

            //SupportedGroupsExtension.TryParse(afterSignatureAlgorithms1, out var supportedGroups1, out var afterSupportedGroups1);

            //TransportParametersExtension.TryParse(afterSupportedGroups1, out var transportParametersExtension1, out var afterTransportParametersExtension1);

            //PskKeyExchangeModesExtension.TryParse(afterTransportParametersExtension1, out var pskKeyExchangeModes1, out var afterPsk1);

            //var client = DatagramChannel.Start(opt =>
            //{
            //    opt.ListeningPoint = new IPEndPoint(IPAddress.Any, 50000);
            //});

            //var addr = Dns.GetHostAddresses("litespeedtech.com"); //443
            ////var addr = Dns.GetHostAddresses("test.privateoctopus.com"); //4433
            ////var addr = Dns.GetHostAddresses("quant.eggert.org"); //4433
            ////var addr = Dns.GetHostAddresses("f5quic.com"); //4433

            //var dgram = new Datagram().WithAddress(addr[0]).WithPort(443).WithBuffer(buffer.ToArray());

            //client.Writer.TryWrite(dgram);

            //var response = client.Reader.ReadAsync().AsTask().Result;
        }

        static byte[] GetData()
        {
            return File
                .ReadAllText("c:\\test CH 1.txt")
                .Split(new string[] { " ", Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries)
                .Select(bStr => byte.Parse(bStr, NumberStyles.HexNumber))
                .ToArray();
        }

        static byte[] Parse(string str)
        {
            var chars = str.AsSpan();
            var bytes = new List<byte>();

            while(!chars.IsEmpty)
            {
                var b = chars.Slice(0, 2);

                bytes.Add(byte.Parse(b, NumberStyles.HexNumber));

                chars = chars.Slice(2);
            }

            return bytes.ToArray();
        }

        static string Parse(byte[] bytes)
        {
            var result = new StringBuilder();

            foreach(var b in bytes)
            {
                result.Append(b.ToString("X2"));
            }

            return result.ToString();
        }
    }

    public class AesIntrinsicsContext
    {
        private Vector128<byte>[] roundKeys;

        public AesIntrinsicsContext(ReadOnlySpan<byte> key)
        {
            Span<byte> buffer = stackalloc byte[key.Length];

            key.CopyTo(buffer);

            roundKeys = KeyExpansion(buffer);
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public void EncryptEcb(Span<byte> data)
        {
            Vector128<byte>[] keys = roundKeys;
            Span<Vector128<byte>> blocks = MemoryMarshal.Cast<byte, Vector128<byte>>(data);

            for (int i = 0; i < blocks.Length; i++)
            {
                Vector128<byte> b = blocks[i];

                b = Sse2.Xor(b, keys[0]);
                b = Aes.Encrypt(b, keys[1]);
                b = Aes.Encrypt(b, keys[2]);
                b = Aes.Encrypt(b, keys[3]);
                b = Aes.Encrypt(b, keys[4]);
                b = Aes.Encrypt(b, keys[5]);
                b = Aes.Encrypt(b, keys[6]);
                b = Aes.Encrypt(b, keys[7]);
                b = Aes.Encrypt(b, keys[8]);
                b = Aes.Encrypt(b, keys[9]);
                b = Aes.EncryptLast(b, keys[10]);

                blocks[i] = b;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public void DecryptEcb(Span<byte> data)
        {
            Vector128<byte>[] keys = roundKeys;
            Span<Vector128<byte>> blocks = MemoryMarshal.Cast<byte, Vector128<byte>>(data);

            for (int i = 0; i < blocks.Length; i++)
            {
                Vector128<byte> b = blocks[i];

                b = Sse2.Xor(b, keys[10]);
                b = Aes.Decrypt(b, keys[19]);
                b = Aes.Decrypt(b, keys[18]);
                b = Aes.Decrypt(b, keys[17]);
                b = Aes.Decrypt(b, keys[16]);
                b = Aes.Decrypt(b, keys[15]);
                b = Aes.Decrypt(b, keys[14]);
                b = Aes.Decrypt(b, keys[13]);
                b = Aes.Decrypt(b, keys[12]);
                b = Aes.Decrypt(b, keys[11]);
                b = Aes.DecryptLast(b, keys[0]);

                blocks[i] = b;
            }
        }

        private static Vector128<byte>[] KeyExpansion(Span<byte> key)
        {
            var keys = new Vector128<byte>[20];

            keys[0] = Unsafe.ReadUnaligned<Vector128<byte>>(ref key[0]);

            MakeRoundKey(keys, 1, 0x01);
            MakeRoundKey(keys, 2, 0x02);
            MakeRoundKey(keys, 3, 0x04);
            MakeRoundKey(keys, 4, 0x08);
            MakeRoundKey(keys, 5, 0x10);
            MakeRoundKey(keys, 6, 0x20);
            MakeRoundKey(keys, 7, 0x40);
            MakeRoundKey(keys, 8, 0x80);
            MakeRoundKey(keys, 9, 0x1b);
            MakeRoundKey(keys, 10, 0x36);

            for (int i = 1; i < 10; i++)
            {
                keys[10 + i] = Aes.InverseMixColumns(keys[i]);
            }

            return keys;
        }

        private static void MakeRoundKey(Vector128<byte>[] keys, int i, byte rcon)
        {
            Vector128<byte> s = keys[i - 1];
            Vector128<byte> t = keys[i - 1];

            t = Aes.KeygenAssist(t, rcon);
            t = Sse2.Shuffle(t.AsUInt32(), 0xFF).AsByte();

            s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 4));
            s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 8));

            keys[i] = Sse2.Xor(s, t);
        }

        public static bool IsSupported()
        {
            return Aes.IsSupported;
        }
    }
}
