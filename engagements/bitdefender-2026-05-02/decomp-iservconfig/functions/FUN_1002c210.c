void __fastcall FUN_1002c210(undefined4 *param_1,undefined4 *param_2)

{
  code *pcVar1;
  HRESULT HVar2;
  uint uStack_38;
  LPVOID local_1c;
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_10050d50;
  local_10 = ExceptionList;
  uStack_38 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_38;
  ExceptionList = &local_10;
  local_8 = 0;
  local_1c = (LPVOID)0x0;
  local_18 = uStack_38;
  HVar2 = CoCreateInstance((IID *)&DAT_100522b0,(LPUNKNOWN)0x0,1,(IID *)&DAT_10061690,&local_1c);
  local_8 = local_8 & 0xffffff00;
  if (-1 < HVar2) {
    *param_2 = 0;
    param_2[1] = &PTR_vftable_10069aa8;
    *param_1 = local_1c;
    ExceptionList = local_10;
    FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
    return;
  }
  local_1c = (LPVOID)0x0;
  if (HVar2 != -0x7fffbffe) {
    FUN_1002f620(HVar2);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  FUN_1002c2b8(0x80004002,0);
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch@1002c28f @ 1002c28f