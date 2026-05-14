void FUN_140006460(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  code *pcVar1;
  longlong ****pppplVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined1 auStack_148 [32];
  ulonglong local_128 [2];
  undefined8 local_118;
  undefined8 uStack_110;
  undefined8 local_108;
  undefined8 local_f8;
  undefined8 uStack_f0;
  ulonglong local_e8;
  undefined8 uStack_e0;
  undefined8 local_d8;
  undefined8 uStack_d0;
  longlong local_c8 [2];
  undefined8 local_b8;
  undefined8 uStack_b0;
  undefined8 local_a8;
  undefined8 local_98;
  undefined8 uStack_90;
  undefined8 local_88;
  undefined8 local_78;
  undefined8 uStack_70;
  undefined8 local_68;
  undefined8 uStack_60;
  int local_58 [2];
  undefined **local_50;
  longlong ***local_48 [3];
  ulonglong local_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_148;
                    /* WARNING: Load size is inaccurate */
  if ((*(int *)(*ThreadLocalStoragePointer + 4) < DAT_14007d534) &&
     (_Init_thread_header(&DAT_14007d534), DAT_14007d534 == -1)) {
    local_58[0] = 0;
    local_58[1] = 0;
    local_50 = &PTR_vftable_14007ac70;
    FUN_140006180((longlong *)local_48,(undefined8 *)local_58,param_3);
    uVar4 = _UNK_14006e188;
    uVar3 = _DAT_14006e180;
    if ((local_50[1] == DAT_14007ac78) && (local_58[0] == 0)) {
      pppplVar2 = local_48;
      if (7 < local_30) {
        pppplVar2 = (longlong ****)local_48[0];
      }
      FUN_1400045c0(local_128,pppplVar2,local_58);
      uVar3 = local_d8;
      uVar4 = uStack_d0;
      if (7 < local_30) {
        if ((0xfff < local_30 * 2 + 2) &&
           (0x1f < (ulonglong)((longlong)local_48[0] + (-8 - (longlong)local_48[0][-1])))) {
LAB_140006666:
          FUN_140035d28();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        FUN_14002f180();
        uVar3 = local_d8;
        uVar4 = uStack_d0;
      }
    }
    else {
      local_128[0] = 0;
      local_68 = 0;
      uStack_60 = 0;
      local_118 = _DAT_14006e180;
      uStack_110 = _UNK_14006e188;
      local_108 = 0;
      local_f8 = _DAT_14006e180;
      uStack_f0 = _UNK_14006e188;
      local_e8 = 0;
      local_c8[0] = 0;
      local_b8 = _DAT_14006e180;
      uStack_b0 = _UNK_14006e188;
      local_a8 = 0;
      local_98 = _DAT_14006e180;
      uStack_90 = _UNK_14006e188;
      local_88 = 0;
      local_78 = _DAT_14006e180;
      uStack_70 = _UNK_14006e188;
      if (7 < local_30) {
        if ((0xfff < local_30 * 2 + 2) &&
           (0x1f < (ulonglong)((longlong)local_48[0] + (-8 - (longlong)local_48[0][-1]))))
        goto LAB_140006666;
        FUN_14002f180();
      }
    }
    DAT_14007d538 = local_e8;
    uRam000000014007d540 = uStack_e0;
    local_e8 = local_e8 & 0xffffffffffff0000;
    local_d8 = _DAT_14006e180;
    uStack_d0 = _UNK_14006e188;
    _DAT_14007d548 = uVar3;
    DAT_14007d550 = uVar4;
    FUN_1400039f0(local_c8);
    FUN_1400039f0((longlong *)local_128);
    atexit(FUN_14005a320);
    _Init_thread_footer(&DAT_14007d534);
  }
  FUN_14002f160(local_28 ^ (ulonglong)auStack_148);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140006670 @ 140006670

undefined1 (*) [16] FUN_140006670(undefined1 (*param_1) [16])

{
  DWORD DVar1;
  undefined1 (*pauVar2) [16];
  undefined8 *puVar3;
  undefined1 (*pauVar4) [16];
  undefined8 local_58;
  undefined8 uStack_50;
  undefined4 local_48 [4];
  undefined8 local_38 [6];
  
  *(undefined8 *)*param_1 = 0;
  *(undefined8 *)param_1[1] = 0;
  *(undefined8 *)(param_1[1] + 8) = 7;
  *(undefined2 *)*param_1 = 0;
  FUN_14000e410((undefined8 *)param_1,0x7fff,0);
  pauVar2 = param_1;
  if (7 < *(ulonglong *)(param_1[1] + 8)) {
    pauVar2 = *(undefined1 (**) [16])*param_1;
  }
  DVar1 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)pauVar2,0x7fff);
  if (DVar1 == 0) {
    FUN_1400036f0(local_38,(undefined8 *)"GetModuleFileName failed");
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_38,(ThrowInfo *)&DAT_140077a60);
  }
  if (DVar1 == 0x7fff) {
    DVar1 = GetLastError();
    if (DVar1 != 0) {
      FUN_140003730(local_38,DVar1);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_38,(ThrowInfo *)&DAT_140077a60);
    }
  }
  pauVar2 = param_1;
  if (7 < *(ulonglong *)(param_1[1] + 8)) {
    pauVar2 = *(undefined1 (**) [16])*param_1;
  }
  pauVar2 = FUN_14003126c(pauVar2,0x5c);
  if (pauVar2 != (undefined1 (*) [16])0x0) {
    pauVar4 = param_1;
    if (7 < *(ulonglong *)(param_1[1] + 8)) {
      pauVar4 = *(undefined1 (**) [16])*param_1;
    }
    FUN_14000e410((undefined8 *)param_1,
                  (ulonglong)((int)((longlong)pauVar2 - (longlong)pauVar4 >> 1) + 1),0);
    FUN_14000e4b0((longlong *)param_1);
    return param_1;
  }
  puVar3 = (undefined8 *)FUN_1400036d0(local_48,0x1f);
  local_58 = *puVar3;
  uStack_50 = puVar3[1];
  FUN_140003760(local_38,&local_58,(undefined8 *)"GetModuleFileName returned an unexpected path");
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_38,(ThrowInfo *)&DAT_140077a60);
}


// FUNCTION_END

// FUNCTION_START: FUN_1400067c0 @ 1400067c0