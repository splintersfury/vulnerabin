void __fastcall FUN_10003240(int param_1)

{
  int iVar1;
  code *pcVar2;
  HMODULE *ppHVar3;
  void *pvVar4;
  void *local_30 [4];
  undefined4 local_20;
  uint local_1c;
  HMODULE *local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_1004dae0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)(*(int *)(*(int *)(param_1 + -0x60) + 4) + -0x60 + param_1) =
       logger_stream::vftable;
  iVar1 = *(int *)(*(int *)(param_1 + -0x60) + 4);
  *(int *)(iVar1 + -100 + param_1) = iVar1 + -0x60;
  if ((*(char *)(param_1 + -0x18) != '\0') && (DAT_1006b614 + DAT_1006b618 != 0)) {
    local_14 = 0;
    local_18 = FUN_10005210();
    LOCK();
    local_14 = local_14 + 1;
    UNLOCK();
    if (local_18 == (HMODULE *)0x0) {
      local_18 = FUN_10005210();
      LOCK();
      local_14 = local_14 + 1;
      UNLOCK();
    }
    ppHVar3 = local_18;
    FUN_10005a40((void *)(param_1 + -0x5c),local_30);
    FUN_10003200((int)ppHVar3,0,param_1 + -0x14,0x10000000,*(undefined4 *)(param_1 + -0x10),
                 &DAT_1005e418);
    if (7 < local_1c) {
      pvVar4 = local_30[0];
      if ((0xfff < local_1c * 2 + 2) &&
         (pvVar4 = *(void **)((int)local_30[0] + -4),
         0x1f < (uint)((int)local_30[0] + (-4 - (int)pvVar4)))) {
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
      FUN_1002e346(pvVar4);
    }
    local_20 = 0;
    local_30[0] = (void *)((uint)local_30[0] & 0xffff0000);
    local_1c = 7;
    local_18 = (HMODULE *)0x0;
    LOCK();
    UNLOCK();
    iVar1 = local_14;
    while (local_14 = iVar1 + -1, -1 < local_14) {
      FUN_10006030();
      LOCK();
      UNLOCK();
      iVar1 = local_14;
    }
    LOCK();
    UNLOCK();
    local_14 = iVar1;
  }
  *(undefined ***)(*(int *)(*(int *)(param_1 + -0x60) + 4) + -0x60 + param_1) =
       std::
       basic_ostringstream<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
       ::vftable;
  iVar1 = *(int *)(*(int *)(param_1 + -0x60) + 4);
  *(int *)(iVar1 + -100 + param_1) = iVar1 + -0x50;
  FUN_10004db0((undefined4 *)(param_1 + -0x5c));
  *(undefined ***)(*(int *)(*(int *)(param_1 + -0x60) + 4) + -0x60 + param_1) =
       std::basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  iVar1 = *(int *)(*(int *)(param_1 + -0x60) + 4);
  *(int *)(iVar1 + -100 + param_1) = iVar1 + -8;
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100033d0 @ 100033d0