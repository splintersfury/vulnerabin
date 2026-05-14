void FUN_140005940(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                   *param_1,undefined8 *param_2,undefined8 *param_3,undefined8 *param_4)

{
  ulonglong uVar1;
  code *pcVar2;
  ulonglong uVar3;
  longlong lVar4;
  ulonglong uVar5;
  undefined8 ****ppppuVar6;
  CHAR *pCVar7;
  undefined1 auStack_b8 [32];
  undefined8 *local_98;
  undefined8 uStack_90;
  undefined4 local_88;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_80;
  CHAR local_78;
  undefined7 uStack_77;
  ulonglong local_68;
  ulonglong local_60;
  undefined8 ***local_58 [2];
  ulonglong local_48;
  ulonglong local_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_b8;
  *(undefined8 *)param_1 = 0;
  *(undefined8 *)(param_1 + 0x10) = 0;
  *(undefined8 *)(param_1 + 0x18) = 0xf;
  *param_1 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>)0x0;
  local_88 = 1;
  local_80 = param_1;
  uVar3 = __std_fs_code_page();
  uStack_90 = param_3[2];
  if (7 < (ulonglong)param_3[3]) {
    param_3 = (undefined8 *)*param_3;
  }
  local_98 = param_3;
  FUN_1400120c0((LPSTR)local_58,(UINT)uVar3,&local_98);
  uStack_90 = param_4[2];
  if (7 < (ulonglong)param_4[3]) {
    param_4 = (undefined8 *)*param_4;
  }
  local_98 = param_4;
  FUN_1400120c0(&local_78,(UINT)uVar3,&local_98);
  lVar4 = 8;
  if (local_68 == 0) {
    lVar4 = 4;
  }
  uVar5 = lVar4 + param_2[1] + local_68 + local_48;
  uVar3 = *(ulonglong *)(param_1 + 0x10);
  if (uVar3 <= uVar5) {
    uVar1 = *(ulonglong *)(param_1 + 0x18);
    if (uVar1 != uVar5) {
      if (uVar1 < uVar5) {
        FUN_140013390((undefined8 *)param_1,uVar5 - uVar3);
        *(ulonglong *)(param_1 + 0x10) = uVar3;
      }
      else if ((uVar5 < 0x10) && (0xf < uVar1)) {
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
        _Become_small(param_1);
      }
    }
  }
  FUN_140010800((longlong *)param_1,(undefined8 *)*param_2,param_2[1]);
  FUN_140010800((longlong *)param_1,(undefined8 *)&DAT_14006aa2c,3);
  ppppuVar6 = local_58;
  if (0xf < local_40) {
    ppppuVar6 = (undefined8 ****)local_58[0];
  }
  FUN_140010800((longlong *)param_1,ppppuVar6,local_48);
  uVar3 = local_48;
  if (local_68 != 0) {
    FUN_140010800((longlong *)param_1,(undefined8 *)&DAT_14006aa30,4);
    pCVar7 = &local_78;
    if (0xf < local_60) {
      pCVar7 = (CHAR *)CONCAT71(uStack_77,local_78);
    }
    uVar3 = local_68;
    FUN_140010800((longlong *)param_1,(undefined8 *)pCVar7,local_68);
  }
  uVar5 = *(ulonglong *)(param_1 + 0x10);
  uVar1 = *(ulonglong *)(param_1 + 0x18);
  if (uVar5 < uVar1) {
    *(ulonglong *)(param_1 + 0x10) = uVar5 + 1;
    if (0xf < uVar1) {
      param_1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                 param_1;
    }
    *(undefined2 *)(param_1 + uVar5) = 0x22;
  }
  else {
    FUN_1400137e0((undefined8 *)param_1,uVar1,uVar3,0x22);
  }
  if (0xf < local_60) {
    if ((0xfff < local_60 + 1) &&
       (0x1f < (CONCAT71(uStack_77,local_78) - *(longlong *)(CONCAT71(uStack_77,local_78) + -8)) -
               8U)) goto LAB_140005bc4;
    FUN_14002f180();
  }
  local_68 = 0;
  local_60 = 0xf;
  local_78 = '\0';
  if (0xf < local_40) {
    if ((0xfff < local_40 + 1) &&
       (0x1f < (ulonglong)((longlong)local_58[0] + (-8 - (longlong)local_58[0][-1])))) {
      FUN_140035d28();
LAB_140005bc4:
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_14002f180();
  }
  FUN_14002f160(local_38 ^ (ulonglong)auStack_b8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140005bd0 @ 140005bd0