void __fastcall FUN_10004db0(undefined4 *param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  undefined4 *puVar4;
  int iVar5;
  
  *param_1 = std::
             basic_stringbuf<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
             ::vftable;
  if ((*(byte *)(param_1 + 0xf) & 1) != 0) {
    if (*(int *)param_1[8] == 0) {
      iVar5 = *(int *)param_1[7] + *(int *)param_1[0xb] * 2;
    }
    else {
      iVar5 = *(int *)param_1[8] + *(int *)param_1[0xc] * 2;
    }
    pvVar1 = *(void **)param_1[3];
    pvVar3 = pvVar1;
    if ((0xfff < (iVar5 - (int)pvVar1 & 0xfffffffeU)) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
      FUN_10032f7f();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_1002e346(pvVar3);
  }
  *(undefined4 *)param_1[3] = 0;
  *(undefined4 *)param_1[7] = 0;
  *(undefined4 *)param_1[0xb] = 0;
  *(undefined4 *)param_1[4] = 0;
  *(undefined4 *)param_1[8] = 0;
  *(undefined4 *)param_1[0xc] = 0;
  param_1[0xf] = param_1[0xf] & 0xfffffffe;
  param_1[0xe] = 0;
  *param_1 = std::basic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  pvVar1 = (void *)param_1[0xd];
  if (pvVar1 != (void *)0x0) {
    if ((*(int **)((int)pvVar1 + 4) != (int *)0x0) &&
       (puVar4 = (undefined4 *)(**(code **)(**(int **)((int)pvVar1 + 4) + 8))(),
       puVar4 != (undefined4 *)0x0)) {
      (**(code **)*puVar4)(1);
    }
    FUN_1002e346(pvVar1);
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10004e90 @ 10004e90