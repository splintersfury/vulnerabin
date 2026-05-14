void __fastcall FUN_10004750(undefined4 *param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_1004da40;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = ExportedObject<struct_IServConfig>::vftable;
  FUN_100059d0((int)param_1);
  if (7 < (uint)param_1[0xb]) {
    pvVar1 = (void *)param_1[6];
    pvVar3 = pvVar1;
    if ((0xfff < param_1[0xb] * 2 + 2U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
      FUN_10032f7f();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_1002e346(pvVar3);
  }
  param_1[10] = 0;
  param_1[0xb] = 7;
  *(undefined2 *)(param_1 + 6) = 0;
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100047f0 @ 100047f0