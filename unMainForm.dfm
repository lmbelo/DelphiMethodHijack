object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 'MainForm'
  ClientHeight = 270
  ClientWidth = 341
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 0
    Top = 238
    Width = 341
    Height = 32
    Align = alBottom
    Alignment = taCenter
    Caption = 'Label1'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -27
    Font.Name = 'System'
    Font.Style = []
    ParentFont = False
    Layout = tlCenter
    ExplicitTop = 192
    ExplicitWidth = 88
  end
  object Label2: TLabel
    Left = 0
    Top = 0
    Width = 341
    Height = 23
    Align = alTop
    Alignment = taCenter
    Caption = 'Method Hijack'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -19
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
    ExplicitWidth = 119
  end
  object btnApply: TButton
    Left = 8
    Top = 56
    Width = 75
    Height = 25
    Caption = 'Apply'
    TabOrder = 0
    OnClick = btnApplyClick
  end
  object btnUnapply: TButton
    Left = 256
    Top = 56
    Width = 75
    Height = 25
    Caption = 'Unapply'
    TabOrder = 1
    OnClick = btnUnapplyClick
  end
  object btnExecute: TButton
    Left = 130
    Top = 101
    Width = 75
    Height = 25
    Caption = 'Execute'
    TabOrder = 2
    OnClick = btnExecuteClick
  end
  object rgMethod: TRadioGroup
    Left = 0
    Top = 200
    Width = 341
    Height = 38
    Align = alBottom
    Columns = 2
    ItemIndex = 0
    Items.Strings = (
      'VCL Private Method'
      'Self Private Method')
    TabOrder = 3
  end
end
