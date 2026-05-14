void FUN_14002a6a0(longlong *param_1,uint *param_2)

{
  code *pcVar1;
  ulonglong uVar2;
  uint *puVar3;
  undefined8 ****ppppuVar4;
  undefined1 auStack_78 [32];
  undefined4 local_58;
  longlong *local_50;
  undefined8 ***local_48 [2];
  ulonglong local_38;
  ulonglong local_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_78;
  local_58 = 0;
  local_50 = param_1;
  FUN_140017f40((longlong *)local_48,*param_2);
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0xf;
  *(undefined1 *)param_1 = 0;
  local_58 = 1;
  uVar2 = local_38 + 0x15 + *(longlong *)(param_2 + 8);
  if (0xf < uVar2) {
    FUN_140013390(param_1,uVar2);
    param_1[2] = 0;
  }
  FUN_1400106a0(param_1,(undefined8 *)PTR_s_Description__14006e148,0xd);
  puVar3 = param_2 + 4;
  if (0xf < *(ulonglong *)(param_2 + 10)) {
    puVar3 = *(uint **)puVar3;
  }
  FUN_140010800(param_1,(undefined8 *)puVar3,*(ulonglong *)(param_2 + 8));
  FUN_140010800(param_1,(undefined8 *)PTR_s___ec__14006e138,6);
  ppppuVar4 = local_48;
  if (0xf < local_30) {
    ppppuVar4 = (undefined8 ****)local_48[0];
  }
  FUN_140010800(param_1,ppppuVar4,local_38);
  if (0xf < local_30) {
    if ((0xfff < local_30 + 1) &&
       (0x1f < (ulonglong)((longlong)local_48[0] + (-8 - (longlong)local_48[0][-1])))) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  FUN_14002f160(local_28 ^ (ulonglong)auStack_78);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002a7e0 @ 14002a7e0