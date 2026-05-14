undefined8 FUN_140020640(undefined8 *param_1)

{
  undefined4 uVar1;
  uint uVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  undefined1 local_c8 [160];
  
  puVar3 = param_1 + 9;
  if (0xf < (ulonglong)param_1[0xc]) {
    puVar3 = (undefined8 *)param_1[9];
  }
  param_1[0xb] = 0;
  *(undefined1 *)puVar3 = 0;
  puVar3 = (undefined8 *)param_1[6];
  param_1[7] = puVar3;
  local_c8[0] = *(undefined1 *)(param_1 + 2);
  if (puVar3 == (undefined8 *)param_1[8]) {
    FUN_140024dc0(param_1 + 6,puVar3,local_c8);
  }
  else {
    *(undefined1 *)puVar3 = local_c8[0];
    param_1[7] = param_1[7] + 1;
  }
  param_1[3] = param_1[3] + 1;
  param_1[4] = param_1[4] + 1;
  if (*(char *)((longlong)param_1 + 0x14) == '\0') {
    uVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
    *(undefined4 *)(param_1 + 2) = uVar1;
  }
  else {
    *(undefined1 *)((longlong)param_1 + 0x14) = 0;
  }
  if (*(int *)(param_1 + 2) != -1) {
    local_c8[0] = (undefined1)*(int *)(param_1 + 2);
    puVar3 = (undefined8 *)param_1[7];
    if (puVar3 == (undefined8 *)param_1[8]) {
      FUN_140024dc0(param_1 + 6,puVar3,local_c8);
    }
    else {
      *(undefined1 *)puVar3 = local_c8[0];
      param_1[7] = param_1[7] + 1;
    }
  }
  uVar2 = *(int *)(param_1 + 2) + 1;
  if (*(int *)(param_1 + 2) == 10) {
    param_1[5] = param_1[5] + 1;
    param_1[4] = 0;
  }
  else if (0xf5 < uVar2) {
    param_1[0xd] = "invalid string: ill-formed UTF-8 byte";
    return 0xe;
  }
                    /* WARNING: Could not recover jumptable at 0x000140020736. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  uVar4 = (*(code *)(IMAGE_DOS_HEADER_140000000.e_magic +
                    *(uint *)(&DAT_140021014 + (ulonglong)(byte)(&DAT_1400210c4)[(int)uVar2] * 4)))
                    (IMAGE_DOS_HEADER_140000000.e_magic +
                     *(uint *)(&DAT_140021014 + (ulonglong)(byte)(&DAT_1400210c4)[(int)uVar2] * 4));
  return uVar4;
}


// FUNCTION_END

// FUNCTION_START: FUN_140021240 @ 140021240