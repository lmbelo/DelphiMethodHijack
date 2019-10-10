program MethodHijacker;

uses
  Forms,
  unMainForm in 'unMainForm.pas' {MainForm},
  Injector in 'Injector.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
