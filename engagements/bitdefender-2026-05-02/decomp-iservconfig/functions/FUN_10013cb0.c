void __fastcall FUN_10013cb0(undefined4 *param_1)

{
  uint *puVar1;
  int iVar2;
  undefined4 uVar3;
  uint *puVar4;
  undefined1 local_19;
  uint local_18 [5];
  
  local_18[4] = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_18[0] = 0xc;
  puVar4 = local_18;
  local_18[1] = 8;
  local_18[2] = 4;
  local_18[3] = 0;
  while( true ) {
    param_1[4] = param_1[4] + 1;
    param_1[5] = param_1[5] + 1;
    if (*(char *)(param_1 + 3) == '\0') {
      uVar3 = (*(code *)**(undefined4 **)*param_1)();
      param_1[2] = uVar3;
    }
    else {
      *(undefined1 *)(param_1 + 3) = 0;
    }
    if (param_1[2] != -1) {
      puVar1 = (uint *)param_1[8];
      local_19 = (undefined1)param_1[2];
      if (puVar1 == (uint *)param_1[9]) {
        FUN_100174f0(param_1 + 7,puVar1,&local_19);
      }
      else {
        *(undefined1 *)puVar1 = local_19;
        param_1[8] = param_1[8] + 1;
      }
    }
    iVar2 = param_1[2];
    if (iVar2 == 10) break;
    if (((9 < iVar2 - 0x30U) && (5 < iVar2 - 0x41U)) && (5 < iVar2 - 0x61U)) goto LAB_10013d93;
    puVar4 = puVar4 + 1;
    if (puVar4 == local_18 + 4) {
      FUN_1002e315(local_18[4] ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  param_1[6] = param_1[6] + 1;
  param_1[5] = 0;
LAB_10013d93:
  FUN_1002e315(local_18[4] ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10013db0 @ 10013db0