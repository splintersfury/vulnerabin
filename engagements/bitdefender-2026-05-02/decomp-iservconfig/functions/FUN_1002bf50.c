void __thiscall FUN_1002bf50(void *this,int *param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  code *pcVar3;
  int iVar4;
  int *local_24;
  int *local_20;
  int *local_1c;
  int *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10050cf0;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
                    /* WARNING: Load size is inaccurate */
  puVar1 = *this;
  puVar2 = (undefined4 *)*param_1;
  if (puVar1 == puVar2) {
LAB_1002bfe4:
    local_8 = 0;
    puVar1 = *(undefined4 **)((int)this + 4);
    puVar2 = (undefined4 *)param_1[1];
    if (puVar1 == puVar2) goto LAB_1002c04f;
    local_20 = (int *)0x0;
    local_24 = (int *)0x0;
    if (puVar1 != (undefined4 *)0x0) {
      iVar4 = (**(code **)*puVar1)(puVar1,&DAT_10061638,&local_20);
      if (iVar4 < 0) goto LAB_1002c087;
      (**(code **)(*local_20 + 8))(local_20);
    }
    if (puVar2 != (undefined4 *)0x0) {
      iVar4 = (**(code **)*puVar2)(puVar2,&DAT_10061638,&local_24);
      if (iVar4 < 0) goto LAB_1002c094;
      (**(code **)(*local_24 + 8))(local_24);
    }
LAB_1002c04f:
    ExceptionList = local_10;
    FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
    return;
  }
  local_18 = (int *)0x0;
  local_1c = (int *)0x0;
  if (puVar1 == (undefined4 *)0x0) {
LAB_1002bfb9:
    if (puVar2 != (undefined4 *)0x0) {
      iVar4 = (**(code **)*puVar2)(puVar2,&DAT_10061638,&local_1c);
      if (iVar4 < 0) goto LAB_1002c07a;
      (**(code **)(*local_1c + 8))(local_1c);
    }
    if (local_18 != local_1c) goto LAB_1002c04f;
    goto LAB_1002bfe4;
  }
  iVar4 = (**(code **)*puVar1)(puVar1,&DAT_10061638,&local_18,local_14);
  if (-1 < iVar4) {
    (**(code **)(*local_18 + 8))(local_18);
    goto LAB_1002bfb9;
  }
  local_18 = (int *)0x0;
  iVar4 = FUN_1002f620(iVar4);
LAB_1002c07a:
  local_1c = (int *)0x0;
  iVar4 = FUN_1002f620(iVar4);
LAB_1002c087:
  local_20 = (int *)0x0;
  iVar4 = FUN_1002f620(iVar4);
LAB_1002c094:
  local_24 = (int *)0x0;
  FUN_1002f620(iVar4);
  pcVar3 = (code *)swi(3);
  (*pcVar3)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002c0b0 @ 1002c0b0