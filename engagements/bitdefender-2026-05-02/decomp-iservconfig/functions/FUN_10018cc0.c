void __fastcall FUN_10018cc0(LPWSTR param_1,LPCSTR param_2)

{
  uint uVar1;
  code *pcVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  LPWSTR pWVar6;
  int iVar7;
  int extraout_EDX;
  int extraout_EDX_00;
  undefined8 uVar8;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f4ae;
  local_10 = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  uVar1 = *(uint *)(param_2 + 0x10);
  if (0xf < *(uint *)(param_2 + 0x14)) {
    param_2 = *(LPCSTR *)param_2;
  }
  uVar4 = ___std_fs_code_page_0();
  local_8 = 0;
  param_1[0] = L'\0';
  param_1[1] = L'\0';
  param_1[8] = L'\0';
  param_1[9] = L'\0';
  param_1[10] = L'\a';
  param_1[0xb] = L'\0';
  *param_1 = L'\0';
  if (uVar1 == 0) {
LAB_10018d9b:
    ExceptionList = local_10;
    FUN_1002e315(uVar3 ^ (uint)&stack0xfffffffc);
    return;
  }
  if (uVar1 < 0x80000000) {
    uVar8 = ___std_fs_convert_narrow_to_wide_20(uVar4,param_2,uVar1,(LPWSTR)0x0,0);
    iVar7 = (int)((ulonglong)uVar8 >> 0x20);
    uVar5 = (uint)uVar8;
    if (iVar7 == 0) {
      if (*(uint *)(param_1 + 8) < uVar5) {
        FUN_1000f950(param_1,uVar5 - *(uint *)(param_1 + 8),0);
      }
      else {
        pWVar6 = param_1;
        if (7 < *(uint *)(param_1 + 10)) {
          pWVar6 = *(LPWSTR *)param_1;
        }
        *(uint *)(param_1 + 8) = uVar5;
        pWVar6[uVar5] = L'\0';
      }
      if (7 < *(uint *)(param_1 + 10)) {
        param_1 = *(LPWSTR *)param_1;
      }
      uVar8 = ___std_fs_convert_narrow_to_wide_20(uVar4,param_2,uVar1,param_1,uVar5);
      iVar7 = (int)((ulonglong)uVar8 >> 0x20);
      if (iVar7 == 0) goto LAB_10018d9b;
      goto LAB_10018dc5;
    }
  }
  else {
    FUN_10009df0();
    iVar7 = extraout_EDX;
  }
  FUN_1000b540(iVar7);
  iVar7 = extraout_EDX_00;
LAB_10018dc5:
  FUN_1000b540(iVar7);
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018dd0 @ 10018dd0