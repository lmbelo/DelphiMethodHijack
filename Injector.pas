(**************************************************************************)
(*                                                                        *)
(* Module:  Unit 'Injector'         Copyright (c) 2019                    *)
(*                                                                        *)
(*                                  Lucas Moura Belo - lmbelo             *)
(*                                  lucas.belo@live.com                   *)
(*                                  Brazil                                *)
(*                                                                        *)
(* Project page:           https://github.com/lmbelo/DelphiMethodHijack   *)
(**************************************************************************)
(*  Functionality:  Method Hijack.                                        *)
(*                                                                        *)
(*                                                                        *)
(**************************************************************************)
(* This source code is distributed with no WARRANTY, for no reason or use.*)
(* Everyone is allowed to use and change this code free for his own tasks *)
(* and projects, as long as this header and its copyright text is intact. *)
(* For changed versions of this code, which are public distributed the    *)
(* following additional conditions have to be fullfilled:                 *)
(* 1) The header has to contain a comment on the change and the author of *)
(*    it.                                                                 *)
(* 2) A copy of the changed source has to be sent to the above E-Mail     *)
(*    address or my then valid address, if this is possible to the        *)
(*    author.                                                             *)
(* The second condition has the target to maintain an up to date central  *)
(* version of the component. If this condition is not acceptable for      *)
(* confidential or legal reasons, everyone is free to derive a component  *)
(* or to generate a diff file to my or other original sources.            *)
(**************************************************************************)
unit Injector;

interface

type
  TInjector = class
  strict private
    type
      TInjection = packed record
        JMP: byte;
        Offset: integer;
      end;

      PWin9xDebugThunk = ^TWin9xDebugThunk;
      TWin9xDebugThunk = packed record
        PUSH: byte;
        Addr: pointer;
        JMP: byte;
        Offset: integer;
      end;

      PAbsoluteIndirectJmp = ^TAbsoluteIndirectJmp;
      TAbsoluteIndirectJmp = packed record
        OpCode: word;
        Addr: PPointer;
      end;
  private
    FFromAddr: pointer;
    FToAddr: pointer;
    FInjection: TInjection;
    class function IsWin9xDebugThunk(const AAddr: pointer): boolean; static;
  public
    constructor Create(const AFromAddr, AToAddr: pointer);
    destructor Destroy; override;

    procedure Enable;
    procedure Disable;

    class function GetActualAddr(AAddr: pointer): pointer; static;

    class function GetAddressOf(const AAddr: pointer; const AOffsetInBytes: integer): pointer; overload;
    class function GetAddressOf(const AAddr: pointer; const ASignature: array of byte): pointer; overload;

    class function GetAddresOfByACallNearRel(const AAddr: pointer; const AOffsetInBytes: integer): pointer; overload;
    class function GetAddresOfByACallNearRel(const AAddr: pointer; const ASignature: array of byte): pointer; overload;

    class function IsValidCall(const AAddr: pointer): boolean; overload;
    class function IsValidCall(const AAddr: pointer; const AOffsetInBytes: integer): boolean; overload;
    class function IsValidCall(const AAddr: pointer; const ASignature: array of byte): boolean; overload;
  end;

implementation

uses
  SysUtils, Windows;

{ TMocker }

constructor TInjector.Create(const AFromAddr, AToAddr: pointer);
begin
  FFromAddr := AFromAddr;
  FToAddr := AToAddr;
  Enable;
end;

destructor TInjector.Destroy;
begin
  try
    Disable;
  finally
    inherited;
  end;
end;

procedure TInjector.Disable;
var
  LNumBytesWritten: NativeUInt;
begin
  if FInjection.JMP <> 0 then begin
    WriteProcessMemory(GetCurrentProcess, GetActualAddr(FFromAddr), @FInjection, NativeUInt(SizeOf(TInjection)), LNumBytesWritten);
  end;
end;

procedure TInjector.Enable;
var
  LActualAddr: pointer;
  LProtect: DWord;
begin
  if Assigned(FFromAddr) then begin
    LActualAddr := GetActualAddr(FFromAddr);
    if VirtualProtect(LActualAddr, SizeOf(TInjection), PAGE_EXECUTE_READWRITE, LProtect) then begin //Request virtual memory write permission
      FInjection := TInjection(LActualAddr^); //disassembling first 5 bytes
      if (TInjection(LActualAddr^).JMP = $C3) then raise Exception.Create('Can''t hack actual address.'); //Check for a RET instruction. Very small routine may abut another instruction :/
      TInjection(LActualAddr^).JMP := $E9; //overriding first byte with a JMP instruction
      TInjection(LActualAddr^).Offset := Integer(FToAddr) - (Integer(LActualAddr) + SizeOf(TInjection)); //make jump offset to new proc
      VirtualProtect(LActualAddr, SizeOf(TInjection), LProtect, @LProtect); //Restore virtual memory protection
      FlushInstructionCache(GetCurrentProcess, LActualAddr, SizeOf(TInjection)); //flush physical memory
    end;
  end;
end;

class function TInjector.GetActualAddr(AAddr: pointer): pointer;
begin
  if (AAddr <> nil) then begin
    if (Win32Platform <> VER_PLATFORM_WIN32_NT) and IsWin9xDebugThunk(AAddr) then
      AAddr := PWin9xDebugThunk(AAddr).Addr;
    if (PAbsoluteIndirectJmp(AAddr).OpCode = $25FF) then
      Result := PAbsoluteIndirectJmp(AAddr).Addr^
    else
      Result := AAddr;
  end else Result := nil;
end;

class function TInjector.GetAddressOf(const AAddr: pointer;
  const AOffsetInBytes: integer): pointer;
var
  LActualAddr: PByteArray;
begin
  LActualAddr := GetActualAddr(AAddr);
  Inc(PByte(LActualAddr), AOffsetInBytes);
  Result := Pointer(Integer(@LActualAddr[5]) + PInteger(@LActualAddr[1])^);
end;

class function TInjector.GetAddresOfByACallNearRel(const AAddr: pointer;
  const AOffsetInBytes: integer): pointer;
begin
  if not IsValidCall(AAddr, AOffsetInBytes) then
    raise Exception.Create('Offset to address isn''t a valid call');

  Result := GetAddressOf(AAddr, AOffsetInBytes);
end;

class function TInjector.GetAddresOfByACallNearRel(const AAddr: pointer;
  const ASignature: array of byte): pointer;
begin
  if not IsValidCall(AAddr, ASignature) then
    raise Exception.Create('Offset to address isn''t a valid call');

  Result := GetAddressOf(AAddr, ASignature);
end;

class function TInjector.GetAddressOf(const AAddr: pointer;
  const ASignature: array of byte): pointer;
var
  LActualAddr: PByteArray;
begin
  LActualAddr := GetActualAddr(AAddr);
  while not CompareMem(LActualAddr, @ASignature, Length(ASignature)) do
    Inc(PByte(LActualAddr));
  Result := Pointer(Integer(@LActualAddr[5]) + PInteger(@LActualAddr[1])^);
end;

class function TInjector.IsValidCall(const AAddr: pointer;
  const AOffsetInBytes: integer): boolean;
var
  LActualAddr: PByteArray;
begin
  LActualAddr := GetActualAddr(AAddr);
  Inc(PByte(LActualAddr), AOffsetInBytes);
  Result := IsValidCall(LActualAddr);
end;

class function TInjector.IsValidCall(const AAddr: pointer): boolean;
begin
  Result := PByteArray(AAddr)^[0] = $E8;
end;

class function TInjector.IsWin9xDebugThunk(const AAddr: pointer): boolean;
begin
  Result := (AAddr <> nil)
        and (PWin9xDebugThunk(AAddr).PUSH = $68)
        and (PWin9xDebugThunk(AAddr).JMP = $E9);
end;

class function TInjector.IsValidCall(const AAddr: pointer;
  const ASignature: array of byte): boolean;
var
  LActualAddr: PByteArray;
begin
  LActualAddr := GetActualAddr(AAddr);
  while not CompareMem(LActualAddr, @ASignature, Length(ASignature)) do
    Inc(PByte(LActualAddr));

  Result := IsValidCall(LActualAddr);
end;

end.
