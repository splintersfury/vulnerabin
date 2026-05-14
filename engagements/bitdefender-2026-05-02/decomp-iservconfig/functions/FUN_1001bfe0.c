LPSTR __thiscall FUN_1001bfe0(void *this,LPSTR param_1)

{
  uint uVar1;
  code *pcVar2;
  void *pvVar3;
  LPSTR pCVar4;
  int iVar5;
  int extraout_EDX;
  int extraout_EDX_00;
  undefined8 uVar6;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  pvVar3 = ExceptionList;
  puStack_18 = &LAB_1004f7de;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
  uVar1 = *(uint *)((int)this + 0x10);
  if (7 < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
    this = *this;
  }
  local_14 = 0;
  param_1[0] = '\0';
  param_1[1] = '\0';
  param_1[2] = '\0';
  param_1[3] = '\0';
  param_1[0x10] = '\0';
  param_1[0x11] = '\0';
  param_1[0x12] = '\0';
  param_1[0x13] = '\0';
  param_1[0x14] = '\x0f';
  param_1[0x15] = '\0';
  param_1[0x16] = '\0';
  param_1[0x17] = '\0';
  *param_1 = '\0';
  if (uVar1 == 0) {
    ExceptionList = pvVar3;
    return param_1;
  }
  if (uVar1 < 0x80000000) {
    uVar6 = ___std_fs_convert_wide_to_narrow_20(0xfde9,(LPCWSTR)this,uVar1,(LPSTR)0x0,0);
    iVar5 = (int)((ulonglong)uVar6 >> 0x20);
    if (iVar5 == 0) {
      FUN_10005410(param_1,(uint)uVar6,(char)((ulonglong)uVar6 >> 0x20));
      pCVar4 = param_1;
      if (0xf < *(uint *)(param_1 + 0x14)) {
        pCVar4 = *(LPSTR *)param_1;
      }
      uVar6 = ___std_fs_convert_wide_to_narrow_20(0xfde9,(LPCWSTR)this,uVar1,pCVar4,(uint)uVar6);
      iVar5 = (int)((ulonglong)uVar6 >> 0x20);
      if (iVar5 == 0) {
        ExceptionList = local_1c;
        return param_1;
      }
      goto LAB_1001c0cc;
    }
  }
  else {
    FUN_10009df0();
    iVar5 = extraout_EDX;
  }
  FUN_1000b540(iVar5);
  iVar5 = extraout_EDX_00;
LAB_1001c0cc:
  FUN_1000b540(iVar5);
  pcVar2 = (code *)swi(3);
  pCVar4 = (LPSTR)(*pcVar2)();
  return pCVar4;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001c0e0 @ 1001c0e0