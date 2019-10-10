unit unMainForm;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, Injector, ExtCtrls;

type
  TMainForm = class(TForm)
    btnApply: TButton;
    Label1: TLabel;
    Label2: TLabel;
    btnUnapply: TButton;
    btnExecute: TButton;
    rgMethod: TRadioGroup;
    procedure btnUnapplyClick(Sender: TObject);
    procedure btnExecuteClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure btnApplyClick(Sender: TObject);
  private
    FVCLHijack: TInjector;
    FHijack: TInjector;
    procedure MyMethod;
    procedure MyMethodHijacker;
    procedure ApplyToSelf;
    procedure ApplyToVCL;
    procedure UnapplytoVCL;
    procedure UnapplyToSelf;
  public
    procedure ExecuteMethod;
  end;

  TWinControlPatch = class helper for TWinControl
  public
    procedure UpdateShowingPatch;
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}

const           
  TARGET_CALL_OPCODE: array[0..4] of byte = (
    $E8, $9B, $FE, $FF, $FF
  );

{ TWinControlPatch }

procedure TMainForm.FormCreate(Sender: TObject);
begin
  Label1.Caption := EmptyStr;
end;

procedure TMainForm.btnApplyClick(Sender: TObject);
begin
  case rgMethod.ItemIndex of
    0: ApplyToVCL;
    1: ApplyToSelf;
  end;
end;

procedure TMainForm.ApplyToVCL;
begin
  //Private method hijack
  //Note: code changes result in address changes.
  //For a private method, you must search for a public method that uses the target method
  //and get it's address by opcode (machine code).
  //Invoke Self.UpdateControlState to find UpdateShowing opcode;
  //Run this cocde withou changes and look at the debugger window for method opcode.

  Self.UpdateControlState; //Find UpdateShowing call opcode, than change TARGET_CALL_OPCODE constant
  if not Assigned(FVCLHijack) then begin                               //Offset calc
    FVCLHijack := TInjector.Create(TInjector.GetAddresOfByACallNearRel(@TMainForm.UpdateControlState, TARGET_CALL_OPCODE), @TMainForm.UpdateShowingPatch);
  end;
end;

procedure TMainForm.ApplyToSelf;
begin
  if not Assigned(FHijack) then begin
    FHijack := TInjector.Create(@TMainForm.MyMethod, @TMainForm.MyMethodHijacker);
  end;
end;

procedure TMainForm.btnUnapplyClick(Sender: TObject);
begin
  case rgMethod.ItemIndex of
    0: UnapplytoVCL;
    1: UnapplyToSelf;
  end;               
end;

procedure TMainForm.UnapplyToSelf;
begin
  if Assigned(FHijack) then
    FreeAndNil(FHijack);
end;

procedure TMainForm.UnapplytoVCL;
begin
  if Assigned(FVCLHijack) then
    FreeAndNil(FVCLHijack);
end;

procedure TMainForm.btnExecuteClick(Sender: TObject);
begin
  ExecuteMethod;
  UpdateControlState;
end;

procedure TMainForm.ExecuteMethod;
begin
  MyMethod;
end;

procedure TMainForm.MyMethod;
begin
  Label1.Caption := 'Default MyMethod';
end;

procedure TMainForm.MyMethodHijacker;
begin
  Label1.Caption := 'MyMethod hijacked';
end;

procedure TWinControlPatch.UpdateShowingPatch;
begin
  MainForm.Label1.Caption := 'VCL hijacked!';
end;

end.
