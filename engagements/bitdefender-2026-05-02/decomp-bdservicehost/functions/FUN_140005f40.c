void FUN_140005f40(undefined8 *param_1,LPCWSTR param_2,short *param_3,undefined8 *param_4)

{
  code *pcVar1;
  ulonglong uVar2;
  undefined1 auStack_88 [32];
  longlong local_68 [5];
  undefined8 uStack_40;
  char local_38;
  ulonglong local_30;
  
  local_30 = DAT_14007a060 ^ (ulonglong)auStack_88;
  if (*param_3 == 0) {
    FUN_140003820(param_1,param_2,param_4);
  }
  else {
    local_68[0] = 0;
    local_68[2] = 0;
    local_68[3] = 7;
    uVar2 = 0xffffffffffffffff;
    do {
      uVar2 = uVar2 + 1;
    } while (param_3[uVar2] != 0);
    FUN_140010340(local_68,(undefined8 *)param_3,uVar2);
    FUN_140012190(local_68 + 4,param_2,uVar2,(ushort *)local_68);
    if (7 < (ulonglong)local_68[3]) {
      if ((0xfff < local_68[3] * 2 + 2U) &&
         (0x1f < (local_68[0] - *(longlong *)(local_68[0] + -8)) - 8U)) {
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      FUN_14002f180();
    }
    if (local_38 == '\0') {
      *(undefined4 *)param_4 = 0;
      param_4[1] = &PTR_vftable_14007ac70;
      *param_1 = local_68[4];
    }
    else {
      if (local_38 != '\x01') {
        local_68[0] = 0;
        local_68[1] = 0;
        local_68[2] = 0;
        FUN_14000ec80(local_68);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(local_68,(ThrowInfo *)&DAT_1400777e0);
      }
      *param_4 = local_68[4];
      param_4[1] = uStack_40;
      *param_1 = 0;
    }
  }
  FUN_14002f160(local_30 ^ (ulonglong)auStack_88);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400060a0 @ 1400060a0