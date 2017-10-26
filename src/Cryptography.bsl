
// Computes a Hash-based Message Authentication Code (HMAC)
// RFC 2104 https://www.ietf.org/rfc/rfc2104.txt
//
// Parameters:
//  Key			- BinaryData	- the key to use in the hash algorithm
//  Message		- BinaryData	- the input to compute the hash code for
//  HashFunc	- HashFunction	- the name of the hash algorithm to use for hashing
// 
// Returns:
//  BinaryData - The computed hash code
//

Function HMAC(Val SecretKey, Val Message, Val HashFunc) Export
	
	CheckHashFuncIsSupported(HashFunc);
	
	BlSz = 64;
	
	If SecretKey.Size() > BlSz Then
		SecretKey = Hash(SecretKey, HashFunc);
	EndIf;
	
	EmptyBin = GetBinaryDataFromString("");
	SecretKey = BinLeft(SecretKey, BlSz);
	
	Ê0 = BinRightPad(SecretKey, BlSz, "0x00");
	
	ipad = BinRightPad(EmptyBin, BlSz, "0x36");
	k_ipad = BinBitwiseXOR(Ê0, ipad);
	
	opad = BinRightPad(EmptyBin, BlSz, "0x5C");
	k_opad = BinBitwiseXOR(Ê0, opad);
	
	k_ipad_Message = BinConcat(k_ipad, Message);
	k_opad_Hash = BinConcat(k_opad, Hash(k_ipad_Message, HashFunc));
	res = Hash(k_opad_Hash, HashFunc);
	
	Return res;

EndFunction


Procedure CheckHashFuncIsSupported(HashFunc)

	If HashFunc <> HashFunction.MD5 And	HashFunc <> HashFunction.SHA1 And HashFunc <> HashFunction.SHA256 Then
		Raise "HMAC: unsupported hash function: " + HashFunc;
	EndIf;
	
EndProcedure

Function BinLeft(Val BinaryData, Val CountOfBytes)
	
	DataReader = New DataReader(BinaryData);
	
	MemoryStream = New MemoryStream();
	DataWriter = New DataWriter(MemoryStream);
	
	Buffer = DataReader.ReadIntoBinaryDataBuffer(CountOfBytes);
	DataWriter.WriteBinaryDataBuffer(Buffer);
	
	Return MemoryStream.CloseAndGetBinaryData();
	
EndFunction

Function BinRightPad(Val BinaryData, Val Length, Val HexString)

	PadByte = NumberFromHexString(HexString);
	
	DataReader = New DataReader(BinaryData);
	
	MemoryStream = New MemoryStream();
	DataWriter = New DataWriter(MemoryStream);
	
	Buffer = DataReader.ReadIntoBinaryDataBuffer();
	If Buffer.Size > 0 Then
		DataWriter.WriteBinaryDataBuffer(Buffer);
	EndIf;
	
	For n = Buffer.Size + 1 To Length Do
		DataWriter.WriteByte(PadByte);
	EndDo;
	
	Return MemoryStream.CloseAndGetBinaryData();
	
EndFunction

Function BinBitwiseXOR(Val BinaryData1, Val BinaryData2)
	
	MemoryStream = New MemoryStream();
	DataWriter = New DataWriter(MemoryStream);
	
	DataReader1 = New DataReader(BinaryData1);
	DataReader2 = New DataReader(BinaryData2);
	
	Buffer1 = DataReader1.ReadIntoBinaryDataBuffer();
	Buffer2 = DataReader2.ReadIntoBinaryDataBuffer();
	
	If Buffer1.Size > Buffer2.Size Then
		Buffer1.WriteBitwiseXor(0, Buffer2, Buffer2.Size);
		DataWriter.WriteBinaryDataBuffer(Buffer1);
	Else 
		Buffer2.WriteBitwiseXor(0, Buffer1, Buffer1.Size);
		DataWriter.WriteBinaryDataBuffer(Buffer2);
	EndIf;
	
	res = MemoryStream.CloseAndGetBinaryData();
	Return res;

EndFunction

Function Hash(Val Value, Val HashFunc) Export
	DataHashing = New DataHashing(HashFunc);
	DataHashing.Append(Value);
	Return DataHashing.HashSum;
EndFunction

Function BinConcat(Val BinaryData1, Val BinaryData2)

	MemoryStream = New MemoryStream();
	DataWriter = New DataWriter(MemoryStream);
	
	DataReader1 = New DataReader(BinaryData1);
	DataReader2 = New DataReader(BinaryData2);
	
	Buffer1 = DataReader1.ReadIntoBinaryDataBuffer();
	Buffer2 = DataReader2.ReadIntoBinaryDataBuffer();
	
	DataWriter.WriteBinaryDataBuffer(Buffer1);
	DataWriter.WriteBinaryDataBuffer(Buffer2);
	
	res = MemoryStream.CloseAndGetBinaryData();
	Return res;

EndFunction
