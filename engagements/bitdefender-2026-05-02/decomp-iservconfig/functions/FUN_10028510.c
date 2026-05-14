void __fastcall FUN_10028510(undefined4 *param_1,BYTE *param_2,DWORD param_3)

{
  code *pcVar1;
  BOOL BVar2;
  LPWSTR ***ppppWVar3;
  int local_68 [5];
  int local_54 [5];
  LPWSTR **local_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  uint local_30;
  uint uStack_2c;
  DWORD local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1005064d;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_28 = 0;
  BVar2 = CryptBinaryToStringW(param_2,param_3,0x4000000c,(LPWSTR)0x0,&local_28);
  if (BVar2 == 0) {
    FUN_10027c70(local_54,(uint *)"CryptBinaryToString for size failed");
                    /* WARNING: Subroutine does not return */
    __CxxThrowException_8(local_54,&DAT_10067674);
  }
  if (local_28 < 2) {
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 7;
    *(undefined2 *)param_1 = 0;
  }
  else {
    local_30 = 0;
    uStack_2c = 7;
    local_40 = (LPWSTR **)0x0;
    local_14 = 0;
    if (local_28 == 0) {
      local_30 = local_28;
                    /* WARNING: Ignoring partial resolution of indirect */
      local_40._0_2_ = 0;
    }
    else {
      FUN_1000f950(&local_40,local_28,0);
    }
    ppppWVar3 = &local_40;
    if (7 < uStack_2c) {
      ppppWVar3 = (LPWSTR ***)local_40;
    }
    BVar2 = CryptBinaryToStringW(param_2,param_3,0x4000000c,(LPWSTR)ppppWVar3,&local_28);
    if (BVar2 == 0) {
      FUN_10027c70(local_68,(uint *)"CryptBinaryToString failed");
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_68,&DAT_10067674);
    }
    if (local_28 < 2) {
      *param_1 = 0;
      param_1[4] = 0;
      param_1[5] = 7;
      *(undefined2 *)param_1 = 0;
      if (7 < uStack_2c) {
        ppppWVar3 = (LPWSTR ***)local_40;
        if (0xfff < uStack_2c * 2 + 2) {
          ppppWVar3 = (LPWSTR ***)local_40[-1];
          if (0x1f < (uint)((int)local_40 + (-4 - (int)ppppWVar3))) {
            FUN_10032f7f();
            pcVar1 = (code *)swi(3);
            (*pcVar1)();
            return;
          }
        }
        FUN_1002e346(ppppWVar3);
      }
    }
    else {
      if (local_30 < local_28) {
        FUN_1000f950(&local_40,local_28 - local_30,0);
      }
      else {
        local_30 = local_28;
        ppppWVar3 = &local_40;
        if (7 < uStack_2c) {
          ppppWVar3 = (LPWSTR ***)local_40;
        }
        *(WCHAR *)((int)ppppWVar3 + local_28 * 2) = L'\0';
      }
      FUN_1000ea80((uint *)&local_40);
      *param_1 = 0;
      param_1[4] = 0;
      param_1[5] = 0;
      *param_1 = local_40;
      param_1[1] = uStack_3c;
      param_1[2] = uStack_38;
      param_1[3] = uStack_34;
      *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_2c,local_30);
    }
  }
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10028720 @ 10028720