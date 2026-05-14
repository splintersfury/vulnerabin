void FUN_14000de30(undefined8 *param_1)

{
  longlong lVar1;
  code *pcVar2;
  longlong lVar3;
  
  *param_1 = std::
             basic_stringbuf<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
             ::vftable;
  if ((*(byte *)(param_1 + 0xe) & 1) != 0) {
    if (*(longlong *)param_1[8] == 0) {
      lVar3 = *(longlong *)param_1[7] + (longlong)*(int *)param_1[10] * 2;
    }
    else {
      lVar3 = *(longlong *)param_1[8] + (longlong)*(int *)param_1[0xb] * 2;
    }
    lVar1 = *(longlong *)param_1[3];
    if ((0xfff < (ulonglong)((lVar3 - lVar1 >> 1) * 2)) &&
       (0x1f < (lVar1 - *(longlong *)(lVar1 + -8)) - 8U)) {
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_14002f180();
  }
  *(undefined8 *)param_1[3] = 0;
  *(undefined8 *)param_1[7] = 0;
  *(undefined4 *)param_1[10] = 0;
  *(undefined8 *)param_1[4] = 0;
  *(undefined8 *)param_1[8] = 0;
  *(undefined4 *)param_1[0xb] = 0;
  *(uint *)(param_1 + 0xe) = *(uint *)(param_1 + 0xe) & 0xfffffffe;
  *param_1 = std::basic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  param_1[0xd] = 0;
  if (param_1[0xc] == 0) {
    return;
  }
  if ((*(longlong *)(param_1[0xc] + 8) != 0) &&
     (lVar3 = (*(code *)PTR__guard_dispatch_icall_14005b538)(), lVar3 != 0)) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar3,1);
  }
  FUN_14002f180();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000df40 @ 14000df40