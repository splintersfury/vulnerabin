longlong * FUN_140002e10(longlong *param_1,undefined4 param_2,longlong param_3)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  undefined1 uVar4;
  undefined8 *puVar5;
  _Locimp *p_Var6;
  HMODULE *local_38;
  int local_30;
  
  *param_1 = (longlong)&DAT_14006b6a0;
  param_1[0x14] = 0;
  param_1[0x19] = 0;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0;
  param_1[0x13] = (longlong)std::basic_ios<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  bVar3 = false;
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       std::basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0x10;
  FUN_140011ce0((longlong)*(int *)(*param_1 + 4) + (longlong)param_1,param_1 + 1);
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       std::
       basic_ostringstream<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
       ::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0x88;
  param_1[1] = (longlong)std::basic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  puVar5 = (undefined8 *)operator_new(0x10);
  *puVar5 = 0;
  puVar5[1] = 0;
  p_Var6 = std::locale::_Init(true);
  puVar5[1] = p_Var6;
  param_1[0xd] = (longlong)puVar5;
  param_1[4] = (longlong)(param_1 + 2);
  param_1[5] = (longlong)(param_1 + 3);
  param_1[8] = (longlong)(param_1 + 6);
  param_1[9] = (longlong)(param_1 + 7);
  param_1[0xb] = (longlong)(param_1 + 10);
  param_1[0xc] = (longlong)param_1 + 0x54;
  param_1[3] = 0;
  param_1[7] = 0;
  *(undefined4 *)((longlong)param_1 + 0x54) = 0;
  param_1[2] = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 10) = 0;
  param_1[1] = (longlong)
               std::
               basic_stringbuf<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
               ::vftable;
  param_1[0xe] = 0;
  *(undefined4 *)(param_1 + 0xf) = 4;
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) = logger_stream::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0x98;
  if (DAT_14007d500 + DAT_14007d504 == 0) {
    uVar4 = 0;
  }
  else {
    local_38 = FUN_14000eb20();
    LOCK();
    local_30 = 1;
    UNLOCK();
    bVar3 = true;
    if (local_38 == (HMODULE *)0x0) {
      local_38 = FUN_14000eb20();
      LOCK();
      local_30 = 2;
      UNLOCK();
    }
    if ((*local_38 == (HMODULE)0x0) || (local_38[0xb] == (HMODULE)0x0)) {
      uVar4 = 0;
    }
    else {
      uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
    }
  }
  if (bVar3) {
    LOCK();
    UNLOCK();
    iVar1 = local_30 + -1;
    iVar2 = local_30;
    while (-1 < iVar1) {
      local_30 = iVar2 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar2 + -2;
      iVar2 = local_30;
    }
    LOCK();
    UNLOCK();
  }
  *(undefined1 *)(param_1 + 0x10) = uVar4;
  *(undefined4 *)((longlong)param_1 + 0x84) = param_2;
  param_1[0x11] = param_3;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140003050 @ 140003050