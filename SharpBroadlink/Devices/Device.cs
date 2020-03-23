using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xb.Net;
using Util = Xb.Util;

namespace SharpBroadlink.Devices
{
    /// <summary>
    ///     Base class of devices.
    /// </summary>
    /// <remarks>
    ///     https://github.com/mjg59/python-broadlink/blob/56b2ac36e5a2359272f4af8a49cfaf3e1891733a/broadlink/__init__.py#L142-L291
    /// </remarks>
    public class Device : IDevice, IDisposable
	{
		public static readonly byte[] KeyTemplate
			=
			{
				0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c,
				0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02
			};

		public static readonly byte[] IvTemplate
			=
			{
				0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3,
				0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58
			};

		private int Count;

		private byte[] Key;

		public Device(IPEndPoint host, byte[] mac, int devType, int timeout = 10)
		{
			Host = host;
			Mac = mac;
			DevType = devType;
			Timeout = timeout;

			Key = KeyTemplate;
			Iv = IvTemplate;
			Cs = new Udp(0);

			Count = new Random(int.Parse(DateTime.Now.ToString("HHmmssfff")))
				.Next(0xffff);

			DeviceType = DeviceType.Unknown; // overwrite on subclass
		}

		private byte[] Iv { get; set; }

		private Udp Cs { get; set; }

		private LockObject Lock { get; set; } = new LockObject();


		public IPEndPoint Host { get; private set; }

		public byte[] Mac { get; private set; }

		public int DevType { get; }

		public int Timeout { get; }

		public byte[] Id { get; private set; }
			= {0, 0, 0, 0};

		public DeviceType DeviceType { get; protected set; }

		public async Task<bool> Auth()
		{
			var payload = new List<byte>(new byte[0x50]);

			payload[0x04] = 0x31;
			payload[0x05] = 0x31;
			payload[0x06] = 0x31;
			payload[0x07] = 0x31;
			payload[0x08] = 0x31;
			payload[0x09] = 0x31;
			payload[0x0a] = 0x31;
			payload[0x0b] = 0x31;
			payload[0x0c] = 0x31;
			payload[0x0d] = 0x31;
			payload[0x0e] = 0x31;
			payload[0x0f] = 0x31;
			payload[0x10] = 0x31;
			payload[0x11] = 0x31;
			payload[0x12] = 0x31;
			payload[0x1e] = 0x01;
			payload[0x2d] = 0x01;
			payload[0x30] = (int) 'T';
			payload[0x31] = (int) 'e';
			payload[0x32] = (int) 's';
			payload[0x33] = (int) 't';
			payload[0x34] = (int) ' ';
			payload[0x35] = (int) ' ';
			payload[0x36] = (int) '1';

			var response = await SendPacket(0x65, payload.ToArray());

			if (response == null)
				return false;

			var result = Decrypt(response.Skip(0x38).Take(int.MaxValue).ToArray());

			if (result.Length <= 0)
				return false;

			var key = result.Skip(0x04).Take(16).ToArray();
			if (key.Length % 16 != 0)
				return false;

			Id = result.Take(0x04).ToArray();
			Key = key;

			return true;
		}

		public DeviceType GetDeviceType()
		{
			return DeviceType;
		}

		public async Task<byte[]> SendPacket(int command, byte[] payload)
		{
			Count = (Count + 1) & 0xffff;
			var packet = new List<byte>(new byte[0x38]);
			packet[0x00] = 0x5a;
			packet[0x01] = 0xa5;
			packet[0x02] = 0xaa;
			packet[0x03] = 0x55;
			packet[0x04] = 0x5a;
			packet[0x05] = 0xa5;
			packet[0x06] = 0xaa;
			packet[0x07] = 0x55;
			packet[0x24] = 0x2a;
			packet[0x25] = 0x27;
			packet[0x26] = (byte) command; //UDP-0x5a
			packet[0x28] = (byte) (Count & 0xff);
			packet[0x29] = (byte) (Count >> 8);
			packet[0x2a] = Mac[0];
			packet[0x2b] = Mac[1];
			packet[0x2c] = Mac[2];
			packet[0x2d] = Mac[3];
			packet[0x2e] = Mac[4];
			packet[0x2f] = Mac[5];
			packet[0x30] = Id[0];
			packet[0x31] = Id[1];
			packet[0x32] = Id[2];
			packet[0x33] = Id[3];

			if (payload.Length > 0)
			{
				var numPad = (payload.Length / 16 + 1) * 16;
				var basePayload = payload;
				payload = Enumerable.Repeat((byte) 0x00, numPad).ToArray();
				Array.Copy(basePayload, payload, basePayload.Length);
			}

			var checksum = 0xbeaf;
			foreach (var b in payload)
			{
				checksum += b;
				checksum = checksum & 0xffff;
			}

			packet[0x34] = (byte) (checksum & 0xff);
			packet[0x35] = (byte) (checksum >> 8);

			payload = Encrypt(payload);

			// append 0x38- (UDP-0x62)
			packet.AddRange(payload);

			checksum = 0xbeaf;
			foreach (var b in packet)
			{
				checksum += b;
				checksum = checksum & 0xffff;
			}

			packet[0x20] = (byte) (checksum & 0xff);
			packet[0x21] = (byte) (checksum >> 8);

			RemoteData result = null;
			await Task.Run(() =>
			{
				lock (Lock)
				{
					Lock.IsLocked = true;

					result = Cs
						.SendAndRecieveAsync(packet.ToArray(), Host, Timeout)
						.GetAwaiter()
						.GetResult();

					Lock.IsLocked = false;
				}
			});

			return result?.Bytes;
		}

		protected byte[] Encrypt(byte[] payload)
		{
			using (var aes = new AesManaged())
			{
				aes.KeySize = 256;
				aes.BlockSize = 128;
				aes.Mode = CipherMode.CBC;
				aes.IV = Iv;
				aes.Key = Key;
				//aes.Padding = PaddingMode.PKCS7;
				aes.Padding = PaddingMode.None;

				using (var encryptor = aes.CreateEncryptor())
				using (var toStream = new MemoryStream())
				using (var fromStream = new CryptoStream(toStream, encryptor, CryptoStreamMode.Write))
				{
					fromStream.Write(payload, 0, payload.Length);

					Util.Out($"Encrypt before: {BitConverter.ToString(payload)}");
					Util.Out($"Encrypt after : {BitConverter.ToString(toStream.ToArray())}");

					return toStream.ToArray();
				}
			}
		}

		protected byte[] Decrypt(byte[] payload)
		{
			return Decrypt(payload, 0, payload.Length);
		}

		protected byte[] Decrypt(byte[] payload, int startIndex)
		{
			return Decrypt(payload, startIndex, payload.Length - startIndex);
		}

		protected byte[] Decrypt(byte[] payload, int startIndex, int count)
		{
			using (var aes = new AesManaged())
			{
				aes.KeySize = 256;
				aes.BlockSize = 128;
				aes.Mode = CipherMode.CBC;
				aes.IV = Iv;
				aes.Key = Key;
				//aes.Padding = PaddingMode.PKCS7;
				aes.Padding = PaddingMode.None;

				using (var decryptor = aes.CreateDecryptor())
				using (var fromStream = new MemoryStream(payload, startIndex, count))
				using (var toStream = new CryptoStream(fromStream, decryptor, CryptoStreamMode.Read))
				using (var resultStream = new MemoryStream())
				{
					toStream.CopyTo(resultStream);
					return resultStream.ToArray();
				}
			}
		}

		private class LockObject
		{
			public bool IsLocked { get; set; }
		}

		#region IDisposable Support

		private bool _isDisposed = false; // 重複する呼び出しを検出するには

		protected virtual void Dispose(bool disposing)
		{
			if (!_isDisposed)
			{
				if (disposing)
				{
					if (Cs != null)
					{
						Cs.Dispose();
						Cs = null;
					}

					Host = null;
					Mac = null;
					Id = null;
					Key = null;
					Iv = null;
					Lock = null;
				}

				_isDisposed = true;
			}
		}

		public void Dispose()
		{
			Dispose(true);
		}

		#endregion
	}
}