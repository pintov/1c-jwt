
Function Encode(Val SecretKey, Val Payload = Undefined, Val ExtraHeaders = Undefined) Export
	
	If Payload = Undefined Then
		Payload = New Structure;
	EndIf;
	
	header = New Structure;
	header.Insert("typ", "JWT");
	header.Insert("alg", "HS256");
	If ExtraHeaders <> Undefined Then
		For Each eh In ExtraHeaders Do
			header.Insert(eh.Key, eh.Value);
		EndDo;	
	EndIf;
	
	headerBytes = GetBinaryDataFromString(ComposeJSON(header));
	payloadBytes = GetBinaryDataFromString(ComposeJSON(Payload));
	
	segments = New Array;
	segments.Add(Base64UrlEncode(headerBytes));
	segments.Add(Base64UrlEncode(payloadBytes));
	
	stringToSign = StrConcat(segments, ".");
	
	signature = Cryptography.HMAC(
		GetBinaryDataFromString(SecretKey),
		GetBinaryDataFromString(stringToSign),
		HashFunction.SHA256);
		
	segments.Add(Base64UrlEncode(signature));
	
	res = StrConcat(segments, ".");
	
	Return res;

EndFunction

Function Decode(Val Token, Val SecretKey, Val Verify = True) Export

	parts = StrSplit(Token, ".");
	If parts.Count() <> 3 Then
		Raise "JWT.Decode: Token must consist from 3 delimited by dot parts";
	EndIf;
	
	header = parts[0];
	payload = parts[1];
	crypto = Base64UrlDecode(parts[2]);
	
	headerJson = GetStringFromBinaryData(Base64UrlDecode(header));
	payloadJson = GetStringFromBinaryData(Base64UrlDecode(payload));
	
	headerData = ParseJSON(headerJson);
	payloadData = ParseJSON(payloadJson);
	
	If Verify Then
		If headerData.Property("alg") Then
			If headerData.alg <> "HS256" Then
				Raise "JWT.Decode: unsopported algorithm: " + headerData.alg;
			EndIf;
		Else
			Raise "JWT.Decode: header doesn't contain field 'alg'";
		EndIf;

		signature = Cryptography.HMAC(
			GetBinaryDataFromString(SecretKey),
			GetBinaryDataFromString(header + "." + payload),
			HashFunction.SHA256);
			
		If Base64String(crypto) <> Base64String(signature) Then
			Raise "JWT.Decode: Invalid signature";
		EndIf;
		
	EndIf;
	
	Return payloadData;

EndFunction

Function Base64UrlEncode(Val input)

	output = Base64String(input);
	output = StrSplit(output, "=")[0]; // Remove any trailing '='s
	output = StrReplace(output, Chars.CR + Chars.LF, "");
	output = StrReplace(output, "+", "-"); // 62nd char of encoding
	output = StrReplace(output, "/", "_"); // 63rd char of encoding
	Return output;

EndFunction

Function Base64UrlDecode(Val input)
	
	res = input;
	res = StrReplace(input, "-", "+"); // 62nd char of encoding
	res = StrReplace(res, "_", "/"); // 63rd char of encoding
	m = StrLen(res) % 4;
	If m = 1 Then
		Raise "JWT.Base64UrlDecode: Illegal base64url string: " + input;
	ElsIf m = 2 Then
		res = res + "=="; // Two pad chars
	ElsIf m = 3 Then
		res = res + "="; // One pad char
	EndIf;
	return Base64Value(res);
	
EndFunction

Function ComposeJSON(Obj, LineBreak = Undefined) Export

	If Not ValueIsFilled(Obj) Then
		Return "";
	EndIf;
	
	If LineBreak = Undefined Then
		LineBreak = JSONLineBreak.None;
	EndIf;
	
	JSONWriter = New JSONWriter;
	Settings = New JSONWriterSettings(LineBreak);
	JSONWriter.SetString(Settings);
	WriteJSON(JSONWriter, Obj);
	Return JSONWriter.Close();

EndFunction

Function ParseJSON(Json) Export

	If ValueIsNotFilled(Json) Then
		Return Undefined;
	EndIf;
	
	JSONReader = New JSONReader;
	JSONReader.SetString(Json);
	Return ReadJSON(JSONReader, False);

EndFunction

Procedure Test() Export
	
	SecretKey = "secret";
	Payload = New Structure;
	Payload.Insert("sub", "1234567890");
	Payload.Insert("name", "John Doe");
	Payload.Insert("admin", True);
	
	Token = Encode(SecretKey, Payload);
	
	DecodedPayload = Decode(Token, SecretKey);

EndProcedure