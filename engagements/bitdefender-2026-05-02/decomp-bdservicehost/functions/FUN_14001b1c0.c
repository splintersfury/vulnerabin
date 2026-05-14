void FUN_14001b1c0(longlong *param_1,wchar_t *param_2,undefined8 param_3,LPCSTR ***param_4)

{
  undefined8 uVar1;
  undefined1 auStack_2e8 [48];
  undefined4 local_2b8;
  longlong *local_2b0;
  undefined8 local_298 [9];
  int iStack_24c;
  longlong local_248 [18];
  longlong local_1b8;
  undefined **local_198 [11];
  int iStack_13c;
  longlong local_138 [22];
  undefined **local_88 [12];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_2e8;
  local_2b8 = 0;
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 7;
  *(undefined2 *)param_1 = 0;
  param_1[4] = 0;
  param_1[6] = 0;
  param_1[7] = 7;
  *(undefined2 *)(param_1 + 4) = 0;
  param_1[8] = 0;
  param_1[10] = 0;
  param_1[0xb] = 7;
  *(undefined2 *)(param_1 + 8) = 0;
  param_1[0xc] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 7;
  *(undefined2 *)(param_1 + 0xc) = 0;
  param_1[0x10] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 7;
  *(undefined2 *)(param_1 + 0x10) = 0;
  local_2b0 = param_1;
  FUN_14001d2a0((undefined4 *)(param_1 + 0x15));
  FUN_140031e00((undefined1 (*) [16])local_138,0,0x110);
  uVar1 = 0x110;
  FUN_140031e00((undefined1 (*) [16])local_248,0,0x110);
  FUN_14001ca10(local_248,param_2);
  if (local_1b8 != 0) {
    FUN_14001c870(local_138,local_248);
    local_2b8 = 1;
    *(undefined ***)((longlong)local_248 + (longlong)*(int *)(local_248[0] + 4)) =
         std::basic_ifstream<char,struct_std::char_traits<char>_>::vftable;
    *(int *)((longlong)&iStack_24c + (longlong)*(int *)(local_248[0] + 4)) =
         *(int *)(local_248[0] + 4) + -0xb0;
    FUN_14001c7b0(local_248 + 2);
    *(undefined ***)((longlong)local_248 + (longlong)*(int *)(local_248[0] + 4)) =
         std::basic_istream<char,struct_std::char_traits<char>_>::vftable;
    *(int *)((longlong)&iStack_24c + (longlong)*(int *)(local_248[0] + 4)) =
         *(int *)(local_248[0] + 4) + -0x18;
    local_198[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_198);
    FUN_14001b450(param_1,local_138,uVar1,param_4);
    *(undefined ***)((longlong)local_138 + (longlong)*(int *)(local_138[0] + 4)) =
         std::basic_ifstream<char,struct_std::char_traits<char>_>::vftable;
    *(int *)((longlong)&iStack_13c + (longlong)*(int *)(local_138[0] + 4)) =
         *(int *)(local_138[0] + 4) + -0xb0;
    FUN_14001c7b0(local_138 + 2);
    *(undefined ***)((longlong)local_138 + (longlong)*(int *)(local_138[0] + 4)) =
         std::basic_istream<char,struct_std::char_traits<char>_>::vftable;
    *(int *)((longlong)&iStack_13c + (longlong)*(int *)(local_138[0] + 4)) =
         *(int *)(local_138[0] + 4) + -0x18;
    local_88[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_88);
    FUN_14002f160(local_28 ^ (ulonglong)auStack_2e8);
    return;
  }
  FUN_140001ab0(local_298,0x14006c738);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_298,(ThrowInfo *)&DAT_140077818);
}


// FUNCTION_END

// FUNCTION_START: FUN_14001b440 @ 14001b440