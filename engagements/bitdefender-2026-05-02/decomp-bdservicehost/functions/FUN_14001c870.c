longlong * FUN_14001c870(longlong *param_1,longlong *param_2)

{
  undefined1 uVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  longlong lVar4;
  longlong lVar5;
  
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
  if (param_1 != param_2) {
    FUN_14001d9d0(param_1 + 2);
    lVar4 = (longlong)*(int *)(*param_1 + 4) + (longlong)param_1;
    lVar5 = (longlong)*(int *)(*param_2 + 4) + (longlong)param_2;
    if (lVar4 != lVar5) {
      uVar2 = *(undefined4 *)(lVar4 + 0x10);
      *(undefined4 *)(lVar4 + 0x10) = *(undefined4 *)(lVar5 + 0x10);
      *(undefined4 *)(lVar5 + 0x10) = uVar2;
      uVar2 = *(undefined4 *)(lVar4 + 0x14);
      *(undefined4 *)(lVar4 + 0x14) = *(undefined4 *)(lVar5 + 0x14);
      *(undefined4 *)(lVar5 + 0x14) = uVar2;
      uVar2 = *(undefined4 *)(lVar4 + 0x18);
      *(undefined4 *)(lVar4 + 0x18) = *(undefined4 *)(lVar5 + 0x18);
      *(undefined4 *)(lVar5 + 0x18) = uVar2;
      uVar3 = *(undefined8 *)(lVar4 + 0x20);
      *(undefined8 *)(lVar4 + 0x20) = *(undefined8 *)(lVar5 + 0x20);
      *(undefined8 *)(lVar5 + 0x20) = uVar3;
      uVar3 = *(undefined8 *)(lVar4 + 0x28);
      *(undefined8 *)(lVar4 + 0x28) = *(undefined8 *)(lVar5 + 0x28);
      *(undefined8 *)(lVar5 + 0x28) = uVar3;
      uVar3 = *(undefined8 *)(lVar4 + 0x30);
      *(undefined8 *)(lVar4 + 0x30) = *(undefined8 *)(lVar5 + 0x30);
      *(undefined8 *)(lVar5 + 0x30) = uVar3;
      uVar3 = *(undefined8 *)(lVar4 + 0x38);
      *(undefined8 *)(lVar4 + 0x38) = *(undefined8 *)(lVar5 + 0x38);
      *(undefined8 *)(lVar5 + 0x38) = uVar3;
      uVar3 = *(undefined8 *)(lVar4 + 0x40);
      *(undefined8 *)(lVar4 + 0x40) = *(undefined8 *)(lVar5 + 0x40);
      *(undefined8 *)(lVar5 + 0x40) = uVar3;
    }
    uVar1 = *(undefined1 *)(lVar4 + 0x58);
    *(undefined1 *)(lVar4 + 0x58) = *(undefined1 *)(lVar5 + 0x58);
    *(undefined1 *)(lVar5 + 0x58) = uVar1;
    uVar3 = *(undefined8 *)(lVar4 + 0x50);
    *(undefined8 *)(lVar4 + 0x50) = *(undefined8 *)(lVar5 + 0x50);
    *(undefined8 *)(lVar5 + 0x50) = uVar3;
    lVar4 = param_1[1];
    param_1[1] = param_2[1];
    param_2[1] = lVar4;
    FUN_14001f420((longlong)(param_1 + 2),(longlong)(param_2 + 2));
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001ca10 @ 14001ca10