void FUN_14001c7b0(longlong *param_1)

{
  longlong lVar1;
  longlong lVar2;
  
  *param_1 = (longlong)std::basic_filebuf<char,struct_std::char_traits<char>_>::vftable;
  if ((param_1[0x10] != 0) && (*(longlong **)param_1[3] == param_1 + 0xe)) {
    lVar2 = param_1[0x12];
    lVar1 = param_1[0x11];
    *(longlong *)param_1[3] = lVar1;
    *(longlong *)param_1[7] = lVar1;
    *(int *)param_1[10] = (int)lVar2 - (int)lVar1;
  }
  if (*(char *)((longlong)param_1 + 0x7c) != '\0') {
    FUN_14001d9d0(param_1);
  }
  *param_1 = (longlong)std::basic_streambuf<char,struct_std::char_traits<char>_>::vftable;
  if (param_1[0xc] != 0) {
    if (*(longlong *)(param_1[0xc] + 8) != 0) {
      lVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
      if (lVar2 != 0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar2,1);
      }
    }
    FUN_14002f180();
    return;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001c870 @ 14001c870