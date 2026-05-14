void __fastcall FUN_100025f0(_Locinfo *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_1004da40;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  std::_Locinfo::_Locinfo_dtor(param_1);
  if (*(void **)(param_1 + 0x2c) != (void *)0x0) {
    FUN_100330ca(*(void **)(param_1 + 0x2c));
  }
  *(undefined4 *)(param_1 + 0x2c) = 0;
  if (*(void **)(param_1 + 0x24) != (void *)0x0) {
    FUN_100330ca(*(void **)(param_1 + 0x24));
  }
  *(undefined4 *)(param_1 + 0x24) = 0;
  if (*(void **)(param_1 + 0x1c) != (void *)0x0) {
    FUN_100330ca(*(void **)(param_1 + 0x1c));
  }
  *(undefined4 *)(param_1 + 0x1c) = 0;
  if (*(void **)(param_1 + 0x14) != (void *)0x0) {
    FUN_100330ca(*(void **)(param_1 + 0x14));
  }
  *(undefined4 *)(param_1 + 0x14) = 0;
  if (*(void **)(param_1 + 0xc) != (void *)0x0) {
    FUN_100330ca(*(void **)(param_1 + 0xc));
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  if (*(void **)(param_1 + 4) != (void *)0x0) {
    FUN_100330ca(*(void **)(param_1 + 4));
  }
  *(undefined4 *)(param_1 + 4) = 0;
  FUN_1002c986((int *)param_1);
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100026d0 @ 100026d0