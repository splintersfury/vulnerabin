longlong * FUN_14001ca10(longlong *param_1,wchar_t *param_2)

{
  _iobuf *p_Var1;
  longlong *plVar2;
  longlong lVar3;
  uint uVar4;
  undefined1 local_28 [8];
  longlong local_20;
  
  if (7 < *(ulonglong *)(param_2 + 0xc)) {
    param_2 = *(wchar_t **)param_2;
  }
  *param_1 = (longlong)&DAT_14006d948;
  param_1[0x17] = 0;
  param_1[0x1c] = 0;
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  param_1[0x16] = (longlong)std::basic_ios<char,struct_std::char_traits<char>_>::vftable;
  FUN_14001dff0(param_1,param_1 + 2);
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       std::basic_ifstream<char,struct_std::char_traits<char>_>::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0xb0;
  FUN_14001dac0(param_1 + 2);
  if (param_1[0x12] == 0) {
    p_Var1 = thunk_FUN_14002eb60(param_2,1,0x40);
    if (p_Var1 != (_iobuf *)0x0) {
      FUN_14001d8d0((longlong)(param_1 + 2),(longlong)p_Var1,1);
      local_20 = *(longlong *)(param_1[0xe] + 8);
      (*(code *)PTR__guard_dispatch_icall_14005b538)();
      plVar2 = (longlong *)FUN_140021ed0((longlong)local_28);
      FUN_14001d740((longlong)(param_1 + 2),plVar2);
      if (local_20 != 0) {
        lVar3 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
        if (lVar3 != 0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar3,1);
        }
      }
      goto LAB_14001cb79;
    }
  }
  lVar3 = (longlong)*(int *)(*param_1 + 4) + (longlong)param_1;
  uVar4 = 6;
  if (*(longlong *)(lVar3 + 0x48) != 0) {
    uVar4 = 2;
  }
  FUN_140002cd0(lVar3,uVar4 | *(uint *)(lVar3 + 0x10),'\0');
LAB_14001cb79:
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       std::basic_ifstream<char,struct_std::char_traits<char>_>::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0xb0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001cbb0 @ 14001cbb0