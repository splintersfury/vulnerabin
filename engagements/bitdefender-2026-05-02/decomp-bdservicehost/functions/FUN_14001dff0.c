longlong * FUN_14001dff0(longlong *param_1,undefined8 param_2)

{
  undefined1 uVar1;
  undefined8 *puVar2;
  _Locimp *p_Var3;
  longlong lVar4;
  
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       std::basic_istream<char,struct_std::char_traits<char>_>::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0x18;
  param_1[1] = 0;
  lVar4 = (longlong)*(int *)(*param_1 + 4) + (longlong)param_1;
  *(undefined8 *)(lVar4 + 0x40) = 0;
  *(undefined8 *)(lVar4 + 8) = 0;
  *(undefined4 *)(lVar4 + 0x14) = 0;
  *(undefined4 *)(lVar4 + 0x18) = 0x201;
  *(undefined8 *)(lVar4 + 0x20) = 6;
  *(undefined8 *)(lVar4 + 0x28) = 0;
  *(undefined8 *)(lVar4 + 0x30) = 0;
  *(undefined8 *)(lVar4 + 0x38) = 0;
  *(undefined4 *)(lVar4 + 0x10) = 0;
  puVar2 = (undefined8 *)operator_new(0x10);
  *puVar2 = 0;
  puVar2[1] = 0;
  p_Var3 = std::locale::_Init(true);
  puVar2[1] = p_Var3;
  *(undefined8 **)(lVar4 + 0x40) = puVar2;
  *(undefined8 *)(lVar4 + 0x48) = param_2;
  *(undefined8 *)(lVar4 + 0x50) = 0;
  uVar1 = FUN_14001f7c0(lVar4);
  *(undefined1 *)(lVar4 + 0x58) = uVar1;
  if (*(longlong *)(lVar4 + 0x48) == 0) {
    FUN_140002cd0(lVar4,*(uint *)(lVar4 + 0x10) | 4,'\0');
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001e0d0 @ 14001e0d0